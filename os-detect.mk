# Detect which OS the host is and include the corresponding flags.mk file

UNAME ?= uname

# Include files from this directory
TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifeq ($(OS), Windows_NT)

# Don't use wide characters
HAVE_UNICODE := n

include $(TOPDIR)windows-flags.mk
CC := $(WINCC)

else # !Windows

UNAME_s := $(shell $(UNAME) -s)
ifeq ($(UNAME_s), Linux)
include $(TOPDIR)linux-flags.mk
endif # Linux

endif # Windows
