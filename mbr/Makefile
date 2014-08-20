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

# Skip compilation if compiler don't support 16-bit x86
ifeq ($(shell $(CC) -Werror -E -m16 -march=i386 - < /dev/null > /dev/null 2>&1 && echo y),y)
all: $(BINARIES) all..syslinux-mbr
else
all:
	@echo "Skip compilation as $(CC) can't compile to 16-bit x86 architecture."
endif

%.o: %.S
	$(CC) $(SFLAGS) -c -o $@ $<

%.elf: %.o boot-record.ld
	$(LD) $(LDFLAGS) -T boot-record.ld -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(CHMOD) -x $@

clean: clean..syslinux-mbr
	rm -f *.bin *.elf *.o

%..syslinux-mbr:
	$(MAKE) -C syslinux-mbr $*

.PHONY: all clean %..syslinux-mbr
.PRECIOUS: %.elf %.o
