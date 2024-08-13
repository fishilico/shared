GREP ?= grep
UNAME ?= uname

KERNELVER ?= $(shell $(UNAME) -r)
KERNELPATH ?= /lib/modules/$(KERNELVER)/build
CHECKPATCH ?= $(KERNELPATH)/scripts/checkpatch.pl

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
	$(MAKE) -C $(KERNELPATH) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNELPATH) M=$(CURDIR) clean

# install modules in /lib/modules/$(uname -r)/extra/
install:
	$(MAKE) -C $(KERNELPATH) M=$(CURDIR) modules_install

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
	-Wno-type-limits \
	-Wno-unused-parameter

# Paravirt uses self-initialised local vars
KCFLAGS_WARN += -Wno-uninitialized
# grsec adds an unused-but-set variable
KCFLAGS_WARN += -Wno-error=unused-but-set-variable

# Do not run checkpatch if it would spot SPDX license tags as "C99_COMMENTS"
test: clean
	@KCFLAGS='$(KCFLAGS_WARN)' $(MAKE) all
	@if [ -x $(CHECKPATCH) ] ; then \
		if $(GREP) SPDX_LICENSE_TAG $(CHECKPATCH) > /dev/null ; then \
			$(MAKE) checkpatch ; \
		else \
			echo 'checkpatch is too old to support SPDX-License-Identifier tag, skip it.' ; \
		fi \
	fi

# Run checkpatch on source files
checkpatch:
	$(CHECKPATCH) --no-tree --show-types \
		--file $(filter-out %.mod.c, $(wildcard *.c)) \
		--ignore CONSTANT_COMPARISON \
		--ignore EMBEDDED_FILENAME \
		--ignore LINUX_VERSION_CODE \
		--ignore LONG_LINE \
		--ignore LONG_LINE_COMMENT \
		--ignore LONG_LINE_STRING \
		--ignore MACRO_ARG_UNUSED \
		--ignore REPEATED_WORD

.PHONY: all clean install infos test checkpatch
