.PHONY: module module-clean module-info cycle

all: module

module:
	make -C kernel module

module-clean:
	make -C kernel clean

module-info:
	make -C kernel info

cycle:
	make -C kernel cycle
