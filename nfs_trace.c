/*
 ** NOTE: This example is works on x86 and powerpc.
 ** Here's a sample kernel module showing the use of kprobes to dump a
 ** stack trace and selected registers when do_fork() is called.
 **
 ** For more information on theory of operation of kprobes, see
 ** Documentation/kprobes.txt
 **
 ** You will see the trace data in /var/log/messages and on the console
 ** whenever do_fork() is invoked to create a new process.
 **/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include<linux/types.h>
#include<linux/kdev_t.h>
#include<linux/gfp.h>

#include <linux/printk.h>
#include <linux/err.h>


#define ARG0 (regs->di)
#define ARG1 (regs->si)
#define ARG2 (regs->dx)
#define ARG3 (regs->cx)

#define DEV_NAME "nfs_trace"
#define RINGBUF_SIZE (2 * 1024 * 1024)

#include "rkt_buf.c"

static void _unregister_kprobes(void);
static int _register_kprobes(void);
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr);
static int handler_nfsd_vfs_read(struct kprobe *p, struct pt_regs *regs);

static int nt_open(struct inode *inode, struct file *filp);
static int nt_release(struct inode *inode, struct file *filp);
static ssize_t nt_read(struct file *filp, char __user *usr_buf, size_t count, loff_t *ppos);


static struct kprobe kp_nfsd_vfs_read = {
	.symbol_name	= "nfsd_vfs_read",
	.pre_handler = handler_nfsd_vfs_read,
	.fault_handler = handler_fault,
};

struct file_operations nt_fops = {
  .owner          = THIS_MODULE,
  .open           = nt_open,
  .read           = nt_read,
  .release        = nt_release,
};

typedef struct {
  unsigned int major;
	unsigned int minor;
	struct cdev cdev;
  int in_use;
} nt_dev_t;

static nt_dev_t g_nt_dev;
static struct class * g_device_class;

static char * storage = NULL;
static rkt_buf ringbuf;

// https://elixir.bootlin.com/linux/v2.6.32.71/source/fs/nfsd/vfs.c#L1094
/*
static __be32
nfsd_vfs_read(struct svc_rqst *rqstp, struct svc_fh *fhp, struct file *file,
              loff_t offset, struct kvec *vec, int vlen, unsigned long *count)
*/

static int handler_nfsd_vfs_read(struct kprobe *p, struct pt_regs *regs)
{
	static char buf[256];
	unsigned long inode;
	struct file * file = (struct file *) ARG2;
	char * pathname;
  int size;

  buf[255] = '\n';
	if (file == NULL)
	{
		printk(KERN_INFO "no file\n");
		return 0;
	}

	inode = file->f_path.dentry->d_inode->i_ino;
	pathname = d_path(&file->f_path, buf, 254);

  size = (256 - (pathname - buf)); 

  rkt_buf_write(&ringbuf, pathname, size);

  pr_info("Wrote %d to buf\n", size);
  

	return 0;
}

/*
* fault_handler: this is called if an exception is generated for any
* instruction within the pre- or post-handler, or when Kprobes
* single-steps the probed instruction.
*/
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	return 0;
}

static int _register_kprobes(void)
{
	int ret = 0;
	ret = register_kprobe(&kp_nfsd_vfs_read);
	if (ret < 0) {
		printk(KERN_INFO "register_kprobe nfsd_vfs_read failed, returned %d\n", ret);
		return ret;
	}

	return 0;
}

static void _unregister_kprobes(void)
{
	unregister_kprobe(&kp_nfsd_vfs_read);
}

static int nt_open(struct inode *inode, struct file *filp)
{
  if (g_nt_dev.in_use != 0)
		return -EBUSY;

	g_nt_dev.in_use = 1;
	filp->private_data = (void *)&g_nt_dev;
	pr_info(DEV_NAME " opened\n");
	return 0;
}

static int nt_release(struct inode *inode, struct file *filp)
{
  g_nt_dev.in_use = 0;
	return 0;
}

static ssize_t nt_read(struct file *filp, char __user *usr_buf, size_t len, loff_t *ppos)
{
  int result;
  unsigned int current_level = rkt_buf_level(&ringbuf);

  if (len > current_level) {
      len = current_level;
  }

  result = rkt_buf_read(&ringbuf, usr_buf, len);

  if(result) {
      printk(KERN_ALERT "Error: Rocket-echo buffer read failed with code: %d\n", result);
      return -EFAULT;
  }

  pr_info("Writing %d to user\n", len);

  return len;
}

static int __init kprobe_init(void)
{
	int ret = 0;
	dev_t dev;
	struct device *device;
	int device_num;

  storage = kmalloc(RINGBUF_SIZE, GFP_KERNEL);
  if(storage == NULL) {
    pr_err("%s: failed to allocate ring buf\n", DEV_NAME);
    return -ENOMEM;
  }

  rkt_buf_init(&ringbuf, storage, RINGBUF_SIZE);

	if (alloc_chrdev_region(&dev, 0, 1, DEV_NAME) < 0) {
		pr_err("%s: could not allocate major number\n", DEV_NAME);
		return -ENOMEM;
	}

  g_nt_dev.in_use = 0;
	g_nt_dev.major = MAJOR(dev);
	g_nt_dev.minor = 0;

	g_device_class = class_create(THIS_MODULE, DEV_NAME);
	if (IS_ERR(g_device_class)) {
		pr_err("can't allocate device class\n");
		ret = -EFAULT;
		goto exit_err;
	}

	device_num = MKDEV(g_nt_dev.major, g_nt_dev.minor);
	cdev_init(&g_nt_dev.cdev, &nt_fops);
	if (cdev_add(&g_nt_dev.cdev, device_num, 1) < 0)
  {
		pr_err("%s: chrdev allocation failed\n", DEV_NAME);
		ret = -EFAULT;
		goto exit_err;
  }

	device = device_create(g_device_class, NULL, device_num, NULL, DEV_NAME "%d", 0);
	if (IS_ERR(device))
  {
	  pr_err("%s: device creation  failed\n", DEV_NAME);
	  cdev_del(&g_nt_dev.cdev);
		goto exit_err;
  }

	if (_register_kprobes())
  {
		ret = 1;
    goto exit_err;
  }

  pr_info("nfs_trace started\n");
	return 0;

exit_err:
	cdev_del(&g_nt_dev.cdev);
	if (g_device_class)
		class_destroy(g_device_class);

	unregister_chrdev_region(dev, 1);

	return ret;
	

}

static void __exit kprobe_exit(void)
{
	_unregister_kprobes();

	cdev_del(&g_nt_dev.cdev);
	device_destroy(g_device_class, MKDEV(g_nt_dev.major, g_nt_dev.minor));
  class_destroy(g_device_class);
  unregister_chrdev_region(MKDEV(g_nt_dev.major, g_nt_dev.minor), 1);

  pr_info("nfs_trace stopped\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");

