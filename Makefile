MODULE_NAME := nfs_trace
#$(MODULE_NAME)-objs := rkt_buf.o
obj-m += nfs_trace.o

.PHONY: load unload cycle info

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod $(MODULE_NAME).ko

unload:
	sudo rmmod $(MODULE_NAME)

cycle: all unload load

info:
	modinfo $(MODULE_NAME).ko
