// Copyright (C) 2020 bas smit
// SPDX-License-Identifier:  GPL-2.0-or-later

#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/ioctl.h>

#include <linux/err.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");

#define IOC_MAGIC 'x'
#define NT_DROPPED _IOR(IOC_MAGIC, 1, __u64)
#define NT_EVENTS  _IOR(IOC_MAGIC, 2, __u64)

#define ARG0 (regs->di)
#define ARG1 (regs->si)
#define ARG2 (regs->dx)
#define ARG3 (regs->cx)

#define DEV_NAME "nfs_trace"
#define RING_BUF_SIZE (1024UL * sizeof(nt_ringbuf_entry))

typedef struct {
  char type;
  char path[255];
} nt_ringbuf_entry;

// Buf is full when head == tail -1
typedef struct {
  char *buf;   // storage itself
  __u64 head;  // head pointer offset
  __u64 tail;  // tail pointer offset
  __u64 drops; // dropped due to buffer full
  __u64 events; // total events
  wait_queue_head_t *wq;
} nt_ringbuf;

typedef struct {
  dev_t dev;
  struct cdev cdev;
  wait_queue_head_t wq;
} nt_device;

static void _unregister_kprobes(void);
static int _register_kprobes(void);
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr);
static int handler_nfsd_vfs_read(struct kprobe *p, struct pt_regs *regs);

static int nt_open(struct inode *inode, struct file *filp);
static int nt_release(struct inode *inode, struct file *filp);
static ssize_t nt_read(struct file *filp, char __user *usr_buf, size_t usr_len,
                       loff_t *ppos);
static unsigned int nt_poll(struct file *filp, poll_table *wait);
static long nt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

static int rb_init(nt_ringbuf *rb);
static void rb_free(nt_ringbuf *rb);

static struct kprobe kp_nfsd_vfs_read = {
    .symbol_name = "nfsd_vfs_read",
    .pre_handler = handler_nfsd_vfs_read,
    .fault_handler = handler_fault,
};

struct file_operations g_fops = {
    .owner = THIS_MODULE,
    .open = nt_open,
    .read = nt_read,
    .release = nt_release,
    .poll = nt_poll,
    .unlocked_ioctl = nt_ioctl,
};

static struct class *g_device_class = NULL;
static int g_device_major = 0;
static int g_num_devices = 0;
static int g_consumers = 0;
static nt_device *g_devices = NULL;

static nt_ringbuf *g_ringbufs = NULL;

static DEFINE_MUTEX(g_lock);

static unsigned int nt_poll(struct file *filp, poll_table *wait)
{
  nt_ringbuf *rb = filp->private_data;
  poll_wait(filp, rb->wq, wait);
  if (rb->head != rb->tail)
    return POLLIN | POLLRDNORM;
  return 0;
}

static long nt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  nt_ringbuf *rb = filp->private_data;
  switch (cmd) {
  case NT_DROPPED:
    return rb->drops;
    break;
  case NT_EVENTS:
    return rb->events;
    break;
  default:
    return -EINVAL;
    break;
  }
}

static int nt_open(struct inode *inode, struct file *filp) {
  nt_ringbuf *rb;
  int ret = 0;
  int cpu = iminor(filp->f_path.dentry->d_inode);
  nt_device *dev = container_of(inode->i_cdev, nt_device, cdev);

  if (cpu > g_num_devices) {
    pr_err("cpu(%d) > g_ringbufs(%d)\n", cpu, g_num_devices);
    return -EFAULT;
  }

  mutex_lock(&g_lock);
  rb = &g_ringbufs[cpu];

  if (rb->buf != NULL) {
    ret = -EBUSY;
    goto exit;
  }

  if (rb_init(rb)) {
    ret = -ENOMEM;
    goto exit;
  }

  rb->wq = &dev->wq;

  g_consumers++;
  if (g_consumers == 1)
  {
    if (_register_kprobes() < 0)
    {
      g_consumers--;
      ret = -EIO;
      goto exit;
    }
  }

  filp->private_data = rb;

  pr_info("Consumer registered, total: %d\n", g_consumers);

exit:
  if (ret < 0)
  {
    rb_free(rb);
  }
  mutex_unlock(&g_lock);
  return ret;
}

static int nt_release(struct inode *inode, struct file *filp) {
  mutex_lock(&g_lock);
  rb_free(filp->private_data);
  g_consumers--;
  if (!g_consumers)
    _unregister_kprobes();

  pr_info("Consumer released, total: %d\n", g_consumers);
  mutex_unlock(&g_lock);
  return 0;
}

static ssize_t nt_read(struct file *filp, char __user *usr_buf, size_t usr_len,
                       loff_t *ppos) {
  nt_ringbuf *rb = filp->private_data;
  __u64 head = 0, tail = 0;
  __u64 buf_data = 0, size = 0;
  __s64 remain = 0;

  char __user *usr_buf_orig = usr_buf;
  ssize_t ret = 0;
  int loop_idx = 0;

  if (rb->head == rb->tail) {
    if (filp->f_flags & O_NONBLOCK) {
      return -EAGAIN;
    } else {
      wait_event_interruptible(*rb->wq, rb->head != rb->tail);
    }
  }

  head = rb->head;
  tail = rb->tail;

  // total amount of event data available
  buf_data = (tail < head) ? head - tail : RING_BUF_SIZE - tail + head;

  remain = min(usr_len, buf_data);
  ret = remain;
  while (remain > 0) {
    //
    size = (tail < head) ? head - tail : RING_BUF_SIZE - tail;
    size = min(remain, size);

    // returns the amount of bytes NOT copied
    if (copy_to_user(usr_buf, rb->buf + tail, size))
    {
      pr_info("Failed to copy_to_user to 0x%p(0x%p) 0x%llx 0x%llx\n", usr_buf, usr_buf_orig, tail, size);
      return -EFAULT;
    }

    usr_buf += size;
    remain -= size;
    tail = (tail + size) % RING_BUF_SIZE;

    // Max 2 copies. First is tail to end of buf, second is start to head
    BUG_ON(loop_idx++ > 2);
  }
  BUG_ON(remain < 0);

  rb->tail = tail;
  return ret;
}

// allocate storage for a ringbuf
static int rb_init(nt_ringbuf *rb) {
  rb->head = rb->tail = rb->drops = rb->events = 0;
  rb->buf = vmalloc(RING_BUF_SIZE);
  if (!rb->buf) {
    pr_err("cannot allocate ring buffer storage\n");
    return -ENOMEM;
  }

  return 0;
}

static void rb_free(nt_ringbuf *rb) {
  if (rb->buf)
    vfree(rb->buf);
  rb->head = rb->tail = rb->drops = rb->events = 0;
  rb->buf = NULL;
}

// https://elixir.bootlin.com/linux/v2.6.32.71/source/fs/nfsd/vfs.c#L1094
/*
  static __be32
  nfsd_vfs_read(struct svc_rqst *rqstp, struct svc_fh *fhp, struct file *file,
  loff_t offset, struct kvec *vec, int vlen, unsigned long *count)
*/
static int handler_nfsd_vfs_read(struct kprobe *p, struct pt_regs *regs) {
  char buf[255];
  struct file *file = (struct file *)ARG2;
  char *path;
  int size;
  int cpu;
  nt_ringbuf *rb;
  nt_ringbuf_entry *rbe;
  __u64 head = 0, tail = 0, free = 0;

  if (file == NULL)
    return 0;

  cpu = smp_processor_id();
  rb = &g_ringbufs[cpu];

  // No consumer for this cpu
  if (rb->buf == NULL)
    return 0;

  preempt_disable();

  head = rb->head;
  tail = rb->tail;

  if (tail > head)
    free = tail - head - 1;
  else
    free = RING_BUF_SIZE + tail - head - 1;

  if (likely(free > sizeof(nt_ringbuf_entry))) {
    rbe = (nt_ringbuf_entry *)(rb->buf + head);
    rbe->type = 'r';
    path = d_path(&file->f_path, buf, 254);
    size = 255 - (path - buf);
    memcpy(rbe->path, path, size);

    rb->head = (head + sizeof(nt_ringbuf_entry)) % RING_BUF_SIZE;
    rb->events++;
  } else {
    rb->drops++;
  }
  preempt_enable();

  wake_up_interruptible(rb->wq);
  return 0;
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
  printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
  return 0;
}

static int _register_kprobes(void) {
  int ret = 0;

  // Avoid EINVAL after attach/detach cycle
  kp_nfsd_vfs_read.addr = 0;
  ret = register_kprobe(&kp_nfsd_vfs_read);
  if (ret < 0) {
    pr_info("register_kprobe nfsd_vfs_read failed, returned %d\n", ret);
    return ret;
  }

  pr_info("Kprobe registered\n");
  return 0;
}

static void _unregister_kprobes(void) {
  unregister_kprobe(&kp_nfsd_vfs_read);
  pr_info("Kprobe unregistered\n");
}

static int __init nfs_trace_init(void) {
  int ret = 0;
  dev_t dev = 0;
  struct device *device;
  int idx;

  g_num_devices = num_possible_cpus();

  g_ringbufs = kzalloc(sizeof(nt_ringbuf) * g_num_devices, GFP_KERNEL);
  if (!g_ringbufs) {
    pr_err("could not allocate ringbuf info");
    return -ENOMEM;
  }
  for (idx = 0; idx < g_num_devices; idx++)
    g_ringbufs[idx].buf = 0;

  if (alloc_chrdev_region(&dev, 0, g_num_devices, DEV_NAME) < 0) {
    pr_err("could not allocate major number\n");
    ret = -ENOMEM;
    goto exit_err;
  }

  g_device_class = class_create(THIS_MODULE, DEV_NAME);
  if (IS_ERR(g_device_class)) {
    pr_err("could not allocate device class\n");
    ret = -EFAULT;
    goto exit_err;
  }

  g_device_major = MAJOR(dev);

  g_devices = kmalloc(sizeof(nt_device) * g_num_devices, GFP_KERNEL);
  if (!g_devices) {
    pr_err("could not allocate device array\n");
    ret = -ENOMEM;
    goto exit_err;
  }

  for (idx = 0; idx < g_num_devices; idx++) {
    cdev_init(&g_devices[idx].cdev, &g_fops);
    g_devices[idx].dev = MKDEV(g_device_major, idx);
    if (cdev_add(&g_devices[idx].cdev, g_devices[idx].dev, 1) < 0) {
      pr_err("could not create chardev\n");
      ret = -EFAULT;
      goto exit_err;
    }

    device = device_create(g_device_class, NULL, g_devices[idx].dev, NULL,
                           DEV_NAME "%d", idx);
    if (IS_ERR(device)) {
      pr_err("error creating device\n");
      ret = -EFAULT;
      goto exit_err;
    }
    init_waitqueue_head(&g_devices[idx].wq);
  }

  pr_info("nfs_trace started, major: %d\n", g_device_major);
  return 0;

exit_err:
  if (g_devices) {
    for (idx = 0; idx < g_num_devices; idx++) {
      device_destroy(g_device_class, g_devices[idx].dev);
      cdev_del(&g_devices[idx].cdev);
    }
    kfree(g_devices);
  }
  if (g_device_class)
    class_destroy(g_device_class);

  if (dev)
    unregister_chrdev_region(dev, g_num_devices);

  kfree(g_ringbufs);

  return ret;
}

static void __exit nfs_trace_exit(void) {
  int idx;

  _unregister_kprobes();

  for (idx = 0; idx < g_num_devices; idx++) {
    device_destroy(g_device_class, g_devices[idx].dev);
    cdev_del(&g_devices[idx].cdev);
  }
  kfree(g_devices);
  class_unregister(g_device_class);
  class_destroy(g_device_class);
  unregister_chrdev_region(MKDEV(g_device_major, 0), g_num_devices);

  for (idx = 0; idx < g_num_devices; idx++) {
    rb_free(&g_ringbufs[idx]);
  }
  kfree(g_ringbufs);

  pr_info("nfs_trace stopped\n");
}

module_init(nfs_trace_init) module_exit(nfs_trace_exit)
