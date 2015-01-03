# Run every Makefile in subdirectories
CHMOD ?= chmod
PDFLATEX ?= pdflatex
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
SUBDIRS_BLACKLIST = linux/modules% verification/linux%

# Linux check: filter-out linux/ on non-Linux systems, and boot/ on Windows
ifeq ($(OS), Windows_NT)
SUBDIRS_BLACKLIST += linux% boot%
else ifneq ($(shell $(UNAME) -s 2>/dev/null),Linux)
SUBDIRS_BLACKLIST += linux%
endif

# Windows or MinGW check: compile a basic file
ifneq ($(shell $(WINCC) -E windows/helloworld.c > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += windows%
endif

# boot/ check: only x86 is currently supported
# MBR check: $(CC) needs to be able to produce 16-bit x86
# Syslinux MBR check: $(CC) needs to support some flags
ifneq ($(shell printf '\#if defined(__x86_64__)||defined(__i386__)\ny\n\#endif' |$(CC) -Werror -E - |grep '^[^\#]'),y)
SUBDIRS_BLACKLIST += boot%
else ifneq ($(shell $(CC) -Werror -E -m16 -march=i386 - < /dev/null > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += boot/mbr%
else ifneq ($(shell $(CC) -Werror -E -falign-functions=0 - < /dev/null > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += boot/mbr/syslinux-mbr
endif

# Test PDF-LaTeX availability
ifneq ($(shell $(PDFLATEX) --version > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += latex%
endif

# Build targets
SUBDIRS_FINAL := $(sort $(filter-out $(SUBDIRS_BLACKLIST), $(SUBDIRS)))
ALL_TARGETS := $(addprefix all.., $(SUBDIRS_FINAL))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS_FINAL))
TARGETS := $(ALL_TARGETS) $(CLEAN_TARGETS)

all: $(ALL_TARGETS)

clean: $(CLEAN_TARGETS)

$(TARGETS): TARGET = $(firstword $(subst .., ,$@))
$(TARGETS):
	$(MAKE) -C "$(@:$(TARGET)..%=%)" $(TARGET)

indent-c: gen-indent-c.sh
	$(SH) $< > $@
	$(CHMOD) +x $@

# Sort gen-indent-c.sh types
sort-gen-indent-c: gen-indent-c.sh
	sed -n '1,/<< END-OF-TYPES/p' < $< > .$@.tmp
	sed -n '/<< END-OF-TYPES/,/^END-OF-TYPES/ {/END-OF-TYPES/d;p}' < $< | \
		LANG=C sort >> .$@.tmp
	sed -n '/^END-OF-TYPES/,$$p' < $< >> .$@.tmp
	cat < .$@.tmp > $<
	rm .$@.tmp

.PHONY: all clean $(TARGETS) sort-gen-indent-c
