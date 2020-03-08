# Define some compilation flags for Windows
#
# This file can be both used to compile Windows programs natively or on Linux
# using MinGW.

include $(dir $(lastword $(MAKEFILE_LIST)))common.mk

UNAME ?= uname
WINE ?= wine

# Find a C compiler for windows
ifneq ($(shell mingw32-gcc --version 2> /dev/null),)
	TARGET := mingw32
else
	ARCH := $(shell $(UNAME) -m)
	ifneq ($(shell $(ARCH)-w64-mingw32-gcc --version 2> /dev/null),)
		TARGET := $(ARCH)-w64-mingw32
	else
		ifneq ($(shell $(ARCH)-w32-mingw32-gcc --version 2> /dev/null),)
			TARGET := $(ARCH)-w32-mingw32
		endif
	endif
	TARGET_ARCH := $(call cc-triplet2arch,$(TARGET))
endif

# Using "WINCC ?=" here allows disabling build in windows/ on Linux with:
#   export WINCC=false
ifneq ($(TARGET),)
	WINCC ?= $(TARGET)-gcc
else
	WINCC ?= gcc
endif

# Note: when using the stack protector with wine, libssp-0.dll needs to be found
# by the loader.  On Arch Linux, this can be done with:
#   ln -s /usr/x86_64-w64-mingw32/bin/libssp-0.dll ~/.wine/drive_c/windows/system32/
# As this is buggy, don't enable the stack protector.  It can be enabled with:
#   CFLAGS += -fstack-protector --param=ssp-buffer-size=4
#   LDFLAGS += -fstack-protector
CPPFLAGS = $(@:%=-Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d)
CFLAGS = -O2 -ansi \
	-Wall -Wextra \
	-Waggregate-return \
	-Wformat=2 \
	-Winit-self \
	-Winline \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wmissing-include-dirs \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wold-style-definition \
	-Wpointer-arith \
	-Wshadow \
	-Wstrict-prototypes \
	-Wunknown-pragmas \
	-Wwrite-strings \
	-Wno-long-long \
	-Wno-unused-function
LDFLAGS = -Wl,--subsystem=console,--dynamicbase,--nxcompat
LIBS =


# Enable Unicode if available
HAVE_UNICODE ?= $(call can-run,$(WINCC) -municode -E - < /dev/null)
ifeq ($(HAVE_UNICODE),y)
CPPFLAGS += -D_UNICODE
CFLAGS += -municode
LDFLAGS += -municode
endif

# Application build configuration
BIN_EXT := $(EXT_PREFIX)exe

# Dynamic Linked Library build configuration
LIB_EXT := $(EXT_PREFIX)dll
LIB_CFLAGS =
LIB_LDFLAGS = -shared -Wl,--subsystem=0

# Run tests on Windows or on Linux if wine can be found
HAVE_WINE := $(call can-run,$(WINE) --version)
ifeq ($(HAVE_WINE),y)
	# Use wine to run programs
	ifeq ($(TARGET_ARCH), x86_64)
		# Debian<10 separates 32-bit and 64-bit wine directories so that Wine
		# requires WINEARCH=win64 to run 64-bit programs
		RUN_TEST_PREFIX := WINEARCH=win64 $(WINE)
	else
		RUN_TEST_PREFIX := $(WINE)
	endif
	# On Fedora 32, wine spends too much time terminating, which triggers
	# "wine: a wine server seems to be running, but I cannot connect to it."
	# between some tests
	NEED_WINE_SLEEP := $(call can-run,grep '^CPE_NAME="cpe:/o:fedoraproject:fedora:32"$$' /etc/os-release)
else ifneq ($(OS), Windows_NT)
	# Do not run anything on a non-Windows system without wine
	RUN_TEST_PREFIX := :
endif

ifeq ($(NEED_WINE_SLEEP), y)
	SLEEP_AFTER_WINE_IF_NEEDED := sleep 3
else
	SLEEP_AFTER_WINE_IF_NEEDED := :
endif
