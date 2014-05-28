# Find a C compiler for windows
ifneq ($(shell mingw32-gcc --version 2> /dev/null),)
	TARGET := mingw32
else
	ARCH := $(shell uname -m)
	ifneq ($(shell $(ARCH)-w64-mingw32-gcc --version 2> /dev/null),)
		TARGET := $(ARCH)-w64-mingw32
	else
		ifneq ($(shell $(ARCH)-w32-mingw32-gcc --version 2> /dev/null),)
			TARGET := $(ARCH)-w32-mingw32
		endif
	endif
endif

ifneq ($(TARGET),)
	GCC := $(TARGET)-gcc
else
	GCC ?= gcc
endif
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function \
	-fno-stack-protector --param=ssp-buffer-size=4
LDFLAGS ?= -Wl,-subsystem=windows

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

# Compile things only if windows.h can be included
ifeq ($(shell $(GCC) -E helloworld.c > /dev/null 2>&1 && echo y),y)
all: $(BINARIES)
else
all:
	@echo "Skip compilation as $(GCC) can't compile helloworld.c."
endif

clean:
	rm -f *.exe *.o

helloworld_noimport.exe: LDFLAGS += -nostdlib -Wl,-nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector
check_internals.exe: LDFLAGS += -Wl,-subsystem=console

%.exe: %.o
	$(GCC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(GCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean
