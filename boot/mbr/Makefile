CC ?= cc
LD ?= ld
CHMOD ?= chmod
OBJCOPY ?= objcopy
RM ?= rm -f

CFLAGS = -Wall -fno-stack-protector -fno-exceptions -fvisibility=hidden
SFLAGS = $(CFLAGS)
LDFLAGS =

ifeq ($(CC),gcc)
SFLAGS += -Wa,--fatal-warning
endif

SOURCES := $(wildcard *.S)
ELFS := $(SOURCES:%.S=%.elf)
BINARIES := $(SOURCES:%.S=%.bin)

all: $(BINARIES)

.%.o: %.S
	$(CC) -m32 -march=i386 $(SFLAGS) -c -o $@ $<

%.elf: .%.o boot-record.ld
	$(LD) -m elf_i386 $(LDFLAGS) -T boot-record.ld -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(CHMOD) -x $@

clean:
	$(RM) *.bin *.elf .*.d .*.o

test: all

.PHONY: all clean test
.PRECIOUS: %.elf .%.o

-include .*.d
