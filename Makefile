# Run every Makefile in subdirectories
UNAME ?= uname

# Make does not support ** glob pattern, so only list directory levels by hand
SUBMAKEFILES := $(wildcard */Makefile */*/Makefile */*/*/Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)

# Now filter out subdirectories based on the currently running system
# Include every OS-specific files
include ./linux-flags.mk
include ./windows-flags.mk

# Never build linux/modules from the main Makefile
SUBDIRS_BLACKLIST = linux/modules%

# Linux check
ifneq ($(shell $(UNAME) -s 2>/dev/null),Linux)
SUBDIRS_BLACKLIST += linux%
endif

# Windows or MinGW check: compile a basic file
ifneq ($(shell $(WINCC) -E windows/helloworld.c > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += windows%
endif

# MBR check: $(CC) needs to be able to produce 16-bit x86
ifneq ($(shell $(CC) -Werror -E -m16 -march=i386 - < /dev/null > /dev/null 2>&1 && echo y),y)
SUBDIRS_BLACKLIST += mbr%
endif

# Build targets
SUBDIRS_FINAL := $(filter-out $(SUBDIRS_BLACKLIST), $(SUBDIRS))
ALL_TARGETS := $(addprefix all.., $(SUBDIRS_FINAL))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS_FINAL))
TARGETS := $(ALL_TARGETS) $(CLEAN_TARGETS)

all: $(ALL_TARGETS)

clean: $(CLEAN_TARGETS)

$(TARGETS): TARGET = $(firstword $(subst .., ,$@))
$(TARGETS):
	$(MAKE) -C "$(@:$(TARGET)..%=%)" $(TARGET)

.PHONY: all clean $(TARGETS)
