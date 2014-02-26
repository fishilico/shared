CC ?= cc
# C preprocessor flags
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
# C compiler flags
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 \
	-fPIE
# Linker flags
LDFLAGS ?= -Wl,-z,relro,-z,now -fPIE -pie

# Files
SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)

OBJECTS32 := $(SOURCES:%.c=%.32.o)
OBJECTS64 := $(SOURCES:%.c=%.64.o)
OBJECTS := $(OBJECTS32) $(OBJECTS64)
BINARIES32 := $(SOURCES:%.c=%.32)
BINARIES64 := $(SOURCES:%.c=%.64)
BINARIES := $(BINARIES32) $(BINARIES64)

all: $(BINARIES)

all32: $(BINARIES32)

all64: $(BINARIES64)

clean:
	rm -f $(OBJECTS)

mrproper:
	rm -f $(OBJECTS) $(BINARIES)

%.32: %.32.o
	$(CC) $(LDFLAGS) -m32 -nostdlib -o $@ $^

%.64: %.64.o
	$(CC) $(LDFLAGS) -m64 -nostdlib -o $@ $^

%.32.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -m32 -c -o $@ $<

%.64.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -m64 -c -o $@ $<

.PHONY: all all32 all64 clean mrproper
