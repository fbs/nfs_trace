MODULE_NAME := nfs_trace
obj-m += nfs_trace.o

.PHONY: load unload cycle info

all: module

module: nfs_trace.ko

nfs_trace.ko: nfs_trace.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/kernel clean

load: module
	sudo insmod $(MODULE_NAME).ko

unload: module
	sudo rmmod $(MODULE_NAME) || true

cycle: module unload load

info: module
	modinfo $(MODULE_NAME).ko
