ARCH := $(shell uname -m)
ifeq ($(ARCH), x86_64)
TARGET := x86_64-w64-mingw32
else ifeq ($(ARCH), i686)
TARGET := i686-w32-mingw32
else
TARGET := $(ARCH)-mingw32
endif

GCC := $(TARGET)-gcc
CFLAGS ?= -O2 -Wall -W -Wextra -Wformat=2 \
	-Wmissing-prototypes -Wno-unused-parameter -Wno-unused-function \
	-fstack-protector --param=ssp-buffer-size=4 \
	-municode
LDFLAGS ?= -Wl,-subsystem=windows

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
BINARIES := $(SOURCES:%.c=%.exe)

all: $(BINARIES)

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
