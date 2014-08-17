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
	WINCC := $(TARGET)-gcc
else
	WINCC ?= gcc
endif

# Note: when using the stack protector with wine, libssp-0.dll needs to be found
# by the loader.  On Arch Linux, this can be done with:
#   ln -s /usr/x86_64-w64-mingw32/bin/libssp-0.dll ~/.wine/drive_c/windows/system32/
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function \
	-fstack-protector --param=ssp-buffer-size=4
LDFLAGS ?= -Wl,--subsystem=windows,--dynamicbase,--nxcompat -fstack-protector
LIBS ?=


# Enable Unicode if available
ifeq ($(shell $(WINCC) -municode -E - < /dev/null > /dev/null 2>&1 && echo y),y)
CPPFLAGS += -D_UNICODE
CFLAGS += -municode
LDFLAGS += -municode
endif

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)
ALL_TARGETS := $(addprefix all.., $(SUBDIRS))
CLEAN_TARGETS := $(addprefix clean.., $(SUBDIRS))

# Compile things only if windows.h can be included
ifeq ($(shell $(WINCC) -E helloworld.c > /dev/null 2>&1 && echo y),y)
all: $(BINARIES) $(ALL_TARGETS)
else
all:
	@echo "Skip compilation as $(WINCC) can't compile helloworld.c."
endif

all..%:
	$(MAKE) -C $* all

clean: $(CLEAN_TARGETS)
	rm -f *.exe *.o

clean..%:
	$(MAKE) -C $* clean

helloworld_noimport.exe: LDFLAGS += -nostdlib -Wl,--nostdlib
helloworld_noimport.o: CFLAGS += -nostdlib -fno-stack-protector
check_internals.exe console%.exe list%.exe uuidgen.exe: LDFLAGS += -Wl,--subsystem=console
list_processes.exe: LIBS += -lpsapi
uuidgen.exe: LIBS += -lrpcrt4

%.exe: %.o
	$(WINCC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c $(HEADERS)
	$(WINCC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all all..% clean clean..%
