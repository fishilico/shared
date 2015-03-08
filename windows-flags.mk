# Define some compilation flags for Windows
#
# This file can be both used to compile Windows programs natively or on Linux
# using MinGW.

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
CPPFLAGS ?=
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
ifeq ($(shell $(WINCC) -municode -E - < /dev/null > /dev/null 2>&1 && echo y),y)
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

# Clean command
RM ?= rm -f
CLEAN_CMD := $(RM) *.a *.bin *.dll *.exe *.o *.out *.so *.tmp *.toc .*.d .*.o
