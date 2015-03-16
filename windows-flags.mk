# Define some compilation flags for Windows
#
# This file can be both used to compile Windows programs natively or on Linux
# using MinGW.

include $(dir $(lastword $(MAKEFILE_LIST)))common.mk

UNAME ?= uname

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
CPPFLAGS ?= -Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d
CFLAGS ?= -O2 -ansi \
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
LDFLAGS ?= -Wl,--subsystem=console,--dynamicbase,--nxcompat
LIBS ?=


# Enable Unicode if available
HAVE_UNICODE ?= $(shell $(WINCC) -municode -E - < /dev/null > /dev/null 2>&1 && echo y)
ifeq ($(HAVE_UNICODE),y)
CPPFLAGS += -D_UNICODE
CFLAGS += -municode
LDFLAGS += -municode
endif

# Application build configuration
BIN_EXT := $(EXT_PREFIX)exe

# Dynamic Linked Library build configuration
LIB_EXT := $(EXT_PREFIX)dll
LIB_CFLAGS ?=
LIB_LDFLAGS ?= -shared -Wl,--subsystem=0

# Run tests on Windows or on Linux if binfmt_misc has been configured.
# To configure this, it is possible to run:
#     mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
#     echo ':DOSWin:M::MZ::/usr/bin/wine:' > /proc/sys/fs/binfmt_misc/register
# With systemd, it is possible to configure systemd-binfmt.service by adding a
# file in /etc/binfmt.d/wine.conf containing ':DOSWin:M::MZ::/usr/bin/wine:',
# cf. http://www.freedesktop.org/software/systemd/man/binfmt.d.html
ifeq ($(OS), Windows_NT)
	RUN_WINDOWS_TEST := y
else
	HAVE_WINE_BINFMT := $(shell test -e /proc/sys/fs/binfmt_misc/DOSWin && echo y)
	ifeq ($(HAVE_WINE_BINFMT), y)
		RUN_WINDOWS_TEST := y
	else
		RUN_WINDOWS_TEST := n
	endif
endif
