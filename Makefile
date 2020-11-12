MODULE_NAME := trace_noschedule

obj-m += $(MODULE_NAME).o

KERNEL_HEAD := $(shell uname -r)
KERNELDIR := /lib/modules/$(KERNEL_HEAD)/build
PWD := $(shell pwd)
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
KCPPFLAGS="-mcmodel=large"
endif

all:
	KCPPFLAGS=$(KCPPFLAGS) $(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.mod *.mod.c *.o modules.* Module.symvers

install:
	insmod $(MODULE_NAME).ko

remove:
	rmmod $(MODULE_NAME)
