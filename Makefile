.PHONY: module module-clean module-info cycle

CFLAGS += -Wall -D_FORTIFY_SOURCE=2 -O2 -g -Werror=format-security -Werror=implicit-function-declaration

all: module userspace

module:
	make -C kernel module

module-clean:
	make -C kernel clean

module-info:
	make -C kernel info

module-load:
	make -C kernel load

cycle:
	make -C kernel cycle

userspace: userspace.c
	gcc -std=c99 $(CFLAGS) -o $@ $<
