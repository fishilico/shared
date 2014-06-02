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
# Disable stack protector as it requires linking with libssp DDL, not always provided
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function \
	-fno-stack-protector
LDFLAGS ?= -Wl,--subsystem=windows,--dynamicbase,--nxcompat

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)
ALL_TARGETS := $(addprefix all.., $(SUBDIRS))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS))

# Compile things only if windows.h can be included
ifeq ($(shell $(GCC) -E helloworld.c > /dev/null 2>&1 && echo y),y)
all: $(BINARIES) $(ALL_TARGETS)
else
all:
	@echo "Skip compilation as $(GCC) can't compile helloworld.c."
endif

all..%:
	$(MAKE) -C $* all

clean: $(CLEAN_TARGETS)
	rm -f *.exe *.o

clean..%:
	$(MAKE) -C $* clean

helloworld_noimport.exe: LDFLAGS += -nostdlib -Wl,--nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector
check_internals.exe: LDFLAGS += -Wl,--subsystem=console

%.exe: %.o
	$(GCC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(GCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all all..% clean clean..%
