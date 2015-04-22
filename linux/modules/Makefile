UNAME ?= uname

KERNELVER ?= $(shell $(UNAME) -r)
KERNELPATH ?= /lib/modules/$(KERNELVER)/build

obj-m-$(CONFIG_X86) += cpu_x86.o
obj-m += hello_world.o
obj-m += mmap_file.o
obj-m += proc_setroot.o
obj-m += $(obj-m-y)

# Uncomment to save the prepropressor output to a file
#ccflags-y += -save-temps=obj

all:
	make -C $(KERNELPATH) M=$(CURDIR) modules

clean:
	make -C $(KERNELPATH) M=$(CURDIR) clean

# install modules in /lib/modules/$(uname -r)/extra/
install:
	make -C $(KERNELPATH) M=$(CURDIR) modules_install

# Some targets added to list useful commands
infos:
	modinfo *.ko

test:

.PHONY: all clean install infos test
