# Run every Makefile in subdirectories

# Overridable commands
CHMOD ?= chmod
FIND ?= find
GREP ?= grep
LINUX32 ?= linux32
LINUX64 ?= linux64
PDFLATEX ?= pdflatex
PYTHON ?= python3
RM ?= rm
SED ?= sed
SH ?= sh
UNAME ?= uname

# Make does not support ** glob pattern, so only list directory levels by hand
SUBMAKEFILES := $(wildcard */Makefile */*/Makefile */*/*/Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)

# Now filter out subdirectories based on the currently running system
# Include every OS-specific files
include ./linux-flags.mk
include ./windows-flags.mk

# Never build some specific sub-projects from the main Makefile
SUBDIRS_BLACKLIST =

# Linux check: filter-out linux/ on non-Linux systems, and boot/ on Windows
# If the kernel headers are not installed, filter out linux/modules
ifeq ($(OS),Windows_NT)
SUBDIRS_BLACKLIST += linux% boot%
else ifneq ($(shell $(UNAME) -s 2>/dev/null),Linux)
SUBDIRS_BLACKLIST += linux%
else
KERNELVER ?= $(shell $(UNAME) -r)
KERNELPATH ?= /lib/modules/$(KERNELVER)/build
ifneq ($(call can-run,test -r $(KERNELPATH)/Makefile),y)
SUBDIRS_BLACKLIST += linux/modules%
endif
endif

# Windows or MinGW check: compile a basic file
ifneq ($(call can-run,$(WINCC) -E windows/helloworld.c),y)
SUBDIRS_BLACKLIST += windows%
endif

# boot/ check: only x86 is currently supported
# MBR check: $(CC) needs to support ".code16" asm directive while compiling for x86
# Syslinux MBR check: $(CC) needs to support some flags
hash_sign := \#
ifneq ($(shell printf '$(hash_sign)if defined(__x86_64__)||defined(__i386__)\ny\n$(hash_sign)endif' |$(CC) -Werror -E - |grep '^[^$(hash_sign)]'),y)
SUBDIRS_BLACKLIST += boot%
else ifneq ($(call can-run,echo '__asm__(".code16");' |$(CC) -Werror -m32 -march=i386 -xc -c /dev/stdin -o /dev/null),y)
SUBDIRS_BLACKLIST += boot/mbr%
else ifneq ($(call ccpp-has-option,-falign-functions=0),y)
SUBDIRS_BLACKLIST += boot/mbr/syslinux-mbr
endif

# Fedora 26 to 28 has trouble linking 32-bit EFI applications:
# * F26: ld: BFD version 2.27-28.fc26 assertion fail elf32-i386.c:5545
# * F27: ld: BFD version 2.29-13.fc27 assertion fail elf32-i386.c:5831
# * F28: ld: BFD version 2.29.1-23.fc28 assertion fail elf32-i386.c:5819
TARGET_ARCH := $(call get-cc-target-arch)
ifeq ($(TARGET_ARCH), x86_32)
HAVE_LD_FAILURE := $(call can-run,grep '^CPE_NAME="cpe:/o:fedoraproject:fedora:2[678]"$$' /etc/os-release)
ifeq ($(HAVE_LD_FAILURE), y)
SUBDIRS_BLACKLIST += boot/efi%
endif
endif

# Test Java compiler and runtime availability
ifneq ($(call can-run,$(JAVAC) -version)$(call can-run,$(JAVA) -version),yy)
SUBDIRS_BLACKLIST += java%
endif

# Test PDF-LaTeX availability
ifneq ($(call can-run,$(PDFLATEX) --version),y)
SUBDIRS_BLACKLIST += latex%
endif

# Test python availability
ifneq ($(call can-run,$(PYTHON) --version),y)
SUBDIRS_BLACKLIST += arduino% python% shellcode%
endif

# Test rust/cargo availability
ifneq ($(call can-run,$(CARGO) --version),y)
SUBDIRS_BLACKLIST += rust%
else
# Old versions of rustc (<=1.34) fail to build socket2-0.3.12 because:
#   error[E0658]: use of unstable library feature 'maybe_uninit' (see issue #53491)
#   For more information about this error, try `rustc --explain E0658`.
# Old versions of rustc (<1.38) fail to build object-0.19.0 because:
#   use of unstable library feature 'ptr_cast'
# Old versions of rustc (<=1.39) fail to build subtle-2.3.0 because:
#   error[E0210]: type parameter `T` must be used as the type parameter for some
#   local type (e.g., `MyStruct<T>`)
#   For more information about this error, try `rustc --explain E0210`.
ifeq ($(call can-run,$(RUSTC) --version | grep '^rustc 1\.\(3[0-4]\)\.'),y)
SUBDIRS_BLACKLIST += rust/asymkeyfind% rust/check_linux_pass% rust/download_web%
else ifeq ($(call can-run,$(RUSTC) --version | grep '^rustc 1\.\(3[0-7]\)\.'),y)
SUBDIRS_BLACKLIST += rust/check_linux_pass% rust/download_web%
else ifeq ($(call can-run,$(RUSTC) --version | grep '^rustc 1\.\(3[0-9]\)\.'),y)
SUBDIRS_BLACKLIST += rust/check_linux_pass%
endif
endif

# Show "SUBDIR ..." only if -w and -s and V=1 are not given, and then add
# --no-print-directory to invoked make
ifneq ($(findstring $(MAKEFLAGS), w), w)
ifneq ($(findstring $(MAKEFLAGS), s), s)
ifndef V
_QUIET_SUBDIR := y
define chdir_do
	echo 'DIR '$(1) && \
	$(2) $(MAKE) -C $(1) --no-print-directory $(3)
endef
endif
endif
endif

ifneq ($(_QUIET_SUBDIR), y)
define chdir_do
	$(2) $(MAKE) -C $(1) $(3)
endef
endif

# Build targets
SUBDIRS_FINAL := $(sort $(filter-out $(SUBDIRS_BLACKLIST), $(SUBDIRS)))
ALL_TARGETS := $(addprefix all.., $(SUBDIRS_FINAL))
ALL32_TARGETS := $(addprefix all32.., $(SUBDIRS_FINAL))
ALL64_TARGETS := $(addprefix all64.., $(SUBDIRS_FINAL))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS_FINAL))
TARGETS := $(ALL_TARGETS) $(ALL32_TARGETS) $(ALL64_TARGETS) $(CLEAN_TARGETS)

all: $(ALL_TARGETS) .dockerignore indent-c
	@:

all32: $(ALL32_TARGETS)
	@:

all64: $(ALL64_TARGETS)
	@:

clean: $(CLEAN_TARGETS)

clean-obj:
	$(FIND) . -name '*.o' -delete

test:
	+@for D in $(sort $(SUBDIRS_FINAL)); do \
		($(call chdir_do,$$D,,$@)) || exit $$? ; done

# List programs which are explicitly not built
list-nobuild:
	@echo "Global blacklist: $(sort $(strip $(SUBDIRS_BLACKLIST)))"
	@echo "In sub-directories:"
	@for D in $(sort $(SUBDIRS_FINAL)); do \
		$(GREP) '^$@:' "$$D/Makefile" > /dev/null || continue; \
		echo "   $$D:" $$($(MAKE) -C "$$D" --no-print-directory $@) ; \
		done

# Sync local files with the Internet
sync-inet:
	@for D in $(sort $(SUBDIRS_FINAL)); do \
		$(GREP) '^$@:' "$$D/Makefile" > /dev/null || continue; \
		($(call chdir_do,$$D,,$@)) || exit $$? ; \
		done

$(addprefix all.., $(SUBDIRS)):
	+@$(call chdir_do,$(@:all..%=%),,all)

$(addprefix all32.., $(SUBDIRS)):
	+@$(call chdir_do,$(@:all32..%=%),$(LINUX32),CC="$(CC) -m32" EXT_PREFIX="32." all)

$(addprefix all64.., $(SUBDIRS)):
	+@$(call chdir_do,$(@:all64..%=%),$(LINUX64),CC="$(CC) -m64" EXT_PREFIX="64." all)

$(addprefix clean.., $(SUBDIRS)):
	+@$(call chdir_do,$(@:clean..%=%),,clean)

# Generate a part of .dockerignore from .gitignore
.dockerignore: .gitignore Makefile
	$(SED) -n '1,/^# [.]gitignore/p' < $@ > .$@.tmp
	$(SED) -n 's,^/,,p' $< >> .$@.tmp
	$(SED) -n 's,^[^/#].*,&\n*/&\n*/*/&\n*/*/*/&,p' $< >> .$@.tmp
	cat < .$@.tmp > $@
	$(RM) .$@.tmp

indent-c: gen-indent-c.sh
	$(SH) $< > $@
	$(CHMOD) +x $@

# Sort gen-indent-c.sh types
sort-gen-indent-c: gen-indent-c.sh
	$(SED) -n '1,/<< END-OF-TYPES/p' < $< > .$@.tmp
	$(SED) -n '/<< END-OF-TYPES/,/^END-OF-TYPES/ {/END-OF-TYPES/d;p}' < $< | \
		LANG=C sort >> .$@.tmp
	$(SED) -n '/^END-OF-TYPES/,$$p' < $< >> .$@.tmp
	cat < .$@.tmp > $<
	$(RM) .$@.tmp

.PHONY: all all32 all64 clean clean-obj test list-nobuild sync-inet \
	$(addprefix all.., $(SUBDIRS)) \
	$(addprefix all32.., $(SUBDIRS)) \
	$(addprefix all64.., $(SUBDIRS)) \
	$(addprefix clean.., $(SUBDIRS)) \
	sort-gen-indent-c
