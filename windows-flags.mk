# Find a C compiler for windows

UNAME ?= uname

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
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function
LDFLAGS ?= -Wl,--subsystem=console,--dynamicbase,--nxcompat
LIBS ?=


# Enable Unicode if available
ifeq ($(shell $(WINCC) -municode -E - < /dev/null > /dev/null 2>&1 && echo y),y)
CPPFLAGS += -D_UNICODE
CFLAGS += -municode
LDFLAGS += -municode
endif

# Application build configuration
BIN_EXT := exe

# Dynamic Linked Library build configuration
LIB_EXT := dll
LIB_CFLAGS ?=
LIB_LDFLAGS ?= -shared -Wl,--subsystem=0
