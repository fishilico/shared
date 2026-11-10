CC ?= cc
LD ?= ld
OBJCOPY ?= objcopy
UNAME ?= uname

include ../../common.mk

TARGET_ARCH := $(or $(get-cc-target-arch),unknown-arch)
ifeq ($(TARGET_ARCH),x86_32)
	# Use ARCH=ia32 instead of x86_32 for EFI
	ARCH := ia32
	# Add -m32 flag to enable building 32-bits EFI with "linux32 make"
	CFLAGS += -m32
else
	ARCH := $(TARGET_ARCH)
endif

CPPFLAGS = -Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d
CFLAGS = -O2 -fPIC -Wall -Wextra \
	-ffreestanding \
	-fshort-wchar \
	-fno-strict-aliasing \
	-fno-stack-protector \
	-fno-exceptions \
	-fvisibility=hidden
LDFLAGS = -nostdlib -O1 -T $(CURDIR)/elf_$(ARCH)_efi.lds -shared -Bsymbolic \
	-as-needed -no-undefined -warn-common -fatal-warnings
LIBS =

ifeq ($(ARCH),ia32)
	ARCH_CFLAGS += -mno-mmx -mno-red-zone -mno-sse
else ifeq ($(ARCH),x86_64)
	ARCH_CFLAGS += -mno-red-zone
endif


SOURCES := $(wildcard *.c)
EFI_SOURCES := $(filter-out efi_crt.c, $(SOURCES))
EFIS := $(EFI_SOURCES:%.c=%.efi)


all: $(EFIS)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@:

%.efi: %.so
	$(V_OBJCOPY)$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
		-j .rel* -j .rela* -j .reloc --output-target=efi-app-$(ARCH) $< $@

%.so: .%.o .efi_crt.o
	$(V_LD)$(LD) $(LDFLAGS) $^ -o $@ $(LIBS)

.%.o: %.c efi.h
	$(V_CC)$(CC) $(CFLAGS) $(ARCH_CFLAGS) $(CPPFLAGS) -c $< -o $@

.PHONY: all clean test
.PRECIOUS: %.efi .%.o %.so

-include .*.d
