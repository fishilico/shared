CC = cc
LD = ld
OBJCOPY = objcopy
UNAME = uname

ARCH := $(shell $(UNAME) -m | sed 's,i.86,ia32,')
LDSCRIPT = $(CURDIR)/elf_$(ARCH)_efi.lds

CPPFLAGS =
CFLAGS = -O2 -fPIC -Wall -Wextra \
	-mno-red-zone \
	-fshort-wchar \
	-fno-strict-aliasing \
	-fno-merge-constants \
	-fno-stack-protector \
	-fno-exceptions \
	-fvisibility=hidden
LDFLAGS = -nostdlib -O1 -T $(LDSCRIPT) -shared -Bsymbolic \
	-as-needed -no-undefined -warn-common -fatal-warnings
LIBS =

ifeq ($(ARCH),ia32)
	ARCH_CFLAGS += -mno-mmx -mno-sse
endif


SOURCES := $(wildcard *.c)
EFI_SOURCES := $(filter-out efi_crt.c, $(SOURCES))
EFIS := $(EFI_SOURCES:%.c=%.efi)

# Add -m32 flag to allow building 32-bits EFI with "linux32 make"
ifeq ($(ARCH), ia32)
CFLAGS += -m32
endif

all: $(EFIS)

clean:
	rm -f *.efi *.o *.so

%.efi: %.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel* \
		-j .rela* -j .reloc --target=efi-app-$(ARCH) $< $@

%.so: %.o efi_crt.o
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBS)

%.o: %.c efi.h
	$(CC) $(CFLAGS) $(ARCH_CFLAGS) $(CPPFLAGS) -c $< -o $@

.PHONY: all clean
.PRECIOUS: %.efi %.o %.so
