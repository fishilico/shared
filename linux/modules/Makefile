UNAME ?= uname

KERNELVER ?= $(shell $(UNAME) -r)
KERNELPATH ?= /lib/modules/$(KERNELVER)/build

obj-m-$(CONFIG_ARM) += cpu_arm.o
obj-m-$(CONFIG_X86) += cpu_x86.o
obj-m += hello_world.o
obj-m += mmap_file.o
obj-m += pagetables.o
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

# Build with warnings enabled, and without warnings for kernel headers
KCFLAGS_WARN = -Wall -Wextra -Werror \
	-Waggregate-return \
	-Wfloat-equal \
	-Wformat=2 -Wno-format-nonliteral \
	-Winit-self \
	-Wjump-misses-init \
	-Wlogical-op \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wmissing-include-dirs \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-Wtrampolines \
	-Wunknown-pragmas \
	-Wno-bad-function-cast \
	-Wno-cast-qual \
	-Wno-conversion \
	-Wno-missing-field-initializers \
	-Wno-missing-include-dirs \
	-Wno-nested-externs \
	-Wno-packed \
	-Wno-padded \
	-Wno-pointer-arith \
	-Wno-redundant-decls \
	-Wno-shadow \
	-Wno-sign-conversion \
	-Wno-switch-default \
	-Wno-unused-parameter

# Paravirt uses self-initialised local vars
KCFLAGS_WARN += -Wno-uninitialized
# grsec adds an unused-but-set variable
KCFLAGS_WARN += -Wno-error=unused-but-set-variable

test: clean
	@KCFLAGS='$(KCFLAGS_WARN)' $(MAKE) all
	@if [ -x $(KERNELPATH)/scripts/checkpatch.pl ]; then $(MAKE) checkpatch ; fi

# Run checkpatch on source files
checkpatch:
	$(KERNELPATH)/scripts/checkpatch.pl --no-tree --show-types \
		--file $(filter-out %.mod.c, $(wildcard *.c)) \
		--ignore CONSTANT_COMPARISON \
		--ignore LINUX_VERSION_CODE \
		--ignore LONG_LINE \
		--ignore LONG_LINE_COMMENT \
		--ignore LONG_LINE_STRING

.PHONY: all clean install infos test checkpatch
