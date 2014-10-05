# Detect which OS the host is and include the corresponding flags.mk file

UNAME ?= uname

# Include files from this directory
TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))

ifeq ($(OS), Windows_NT)
include $(TOPDIR)windows-flags.mk
BIN_EXT := exe
CC = $(WINCC)

# Don't use wide characters
CPPFLAGS := $(filter-out -D_UNICODE, $(CPPFLAGS))
CFLAGS := $(filter-out -municode, $(CFLAGS))
LDFLAGS := $(filter-out -municode, $(LDFLAGS))

else # !Windows

BIN_EXT := bin
UNAME_s := $(shell $(UNAME) -s)
ifeq ($(UNAME_s), Linux)
include $(TOPDIR)linux-flags.mk
endif # Linux

endif # Windows
