# Use gcc as clang doesn't support 16-bit code yet
CC = gcc
LD = ld
CHMOD = chmod
OBJCOPY = objcopy

CFLAGS = -Wall -fno-stack-protector -fno-exceptions -fvisibility=hidden
SFLAGS = $(CFLAGS)
LDFLAGS =

ifeq ($(CC),gcc)
SFLAGS += -Wa,--fatal-warning
endif

SOURCES := $(wildcard *.S)
OBJECTS := $(SOURCES:%.S=%.o)
ELFS := $(SOURCES:%.S=%.elf)
BINARIES := $(SOURCES:%.S=%.bin)

all: $(BINARIES)

%.o: %.S
	$(CC) $(SFLAGS) -c -o $@ $<

%.elf: %.o boot-record.ld
	$(LD) $(LDFLAGS) -T boot-record.ld -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(CHMOD) -x $@

clean:
	rm -f *.bin *.elf *.o

.PHONY: all clean
.PRECIOUS: %.elf %.o
