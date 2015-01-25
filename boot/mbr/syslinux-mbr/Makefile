## -----------------------------------------------------------------------
##
##   Copyright 2007-2009 H. Peter Anvin - All Rights Reserved
##   Copyright 2009 Intel Corporation; author: H. Peter Anvin
##
##   This program is free software; you can redistribute it and/or modify
##   it under the terms of the GNU General Public License as published by
##   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
##   Boston MA 02111-1307, USA; either version 2 of the License, or
##   (at your option) any later version; incorporated herein by reference.
##
## -----------------------------------------------------------------------

# Orginal file from Syslinux
# Modified by: Nicolas Iooss

#
# Makefile for MBR
#
CC = gcc
CHMOD = chmod
LD = ld
OBJCOPY = objcopy
UNAME = uname
SED = sed
SHA1SUM = sha1sum

# Architecture definition
SUBARCH := $(shell $(UNAME) -m | $(SED) -e s/i.86/i386/)
# on x86_64, ARCH has trailing whitespace
# strip white spaces in ARCH
ARCH ?= $(strip $(SUBARCH))

# Common warnings we want for all gcc-generated code
GCCWARN  = -W -Wall -Wstrict-prototypes

# Common stanza to make gcc generate .*.d dependency files
MAKEDEPS = -Wp,-MT,$@ -Wp,-MD,$(dir $@).$(notdir $@).d

# Support IA32 and x86_64 platforms with one build
# Set up architecture specifics; for cross compilation, set ARCH as apt
gcc_ok = $(shell tmpf=gcc_ok.$$$$.tmp; \
		if $(CC) $(GCCOPT) $(1) -c dummy.c -o $$tmpf 2>/dev/null ; \
		then echo '$(1)'; \
		elif test -n "$(2)" && $(CC) $(GCCOPT) $(2) -c dummy.c -o $$tmpf 2>/dev/null ; \
		then echo '$(2)'; fi; \
		rm -f $$tmpf)

# Initialize GCCOPT to null to begin with. Without this, make generates
# recursive error for GCCOPT
GCCOPT := -W
GCCOPT += -Os -fomit-frame-pointer -msoft-float
ifeq ($(ARCH),i386)
	GCCOPT := $(call gcc_ok,-m32)
	GCCOPT += $(call gcc_ok,-march=i386)
	GCCOPT += $(call gcc_ok,-mpreferred-stack-boundary=2,)
	GCCOPT += $(call gcc_ok,-mincoming-stack-boundary=2,)
	ifndef EFI_BUILD
		GCCOPT += -mregparm=3 -DREGPARM=3
	endif
endif
ifeq ($(ARCH),x86_64)
	GCCOPT := $(call gcc_ok,-m64)
	GCCOPT += $(call gcc_ok,-march=x86-64)
	GCCOPT += $(call gcc_ok,-fPIC)
endif
GCCOPT += $(call gcc_ok,-ffreestanding,)
GCCOPT += $(call gcc_ok,-fno-stack-protector,)
GCCOPT += $(call gcc_ok,-fwrapv,)
GCCOPT += $(call gcc_ok,-freg-struct-return,)
GCCOPT += $(call gcc_ok,-fno-exceptions,)
GCCOPT += $(call gcc_ok,-fno-asynchronous-unwind-tables,)
GCCOPT += $(call gcc_ok,-fno-strict-aliasing,)
GCCOPT += $(call gcc_ok,-falign-functions=0,-malign-functions=0)
GCCOPT += $(call gcc_ok,-falign-jumps=0,-malign-jumps=0)
GCCOPT += $(call gcc_ok,-falign-labels=0,-malign-labels=0)
GCCOPT += $(call gcc_ok,-falign-loops=0,-malign-loops=0)
GCCOPT += $(call gcc_ok,-fvisibility=hidden)

CFLAGS += $(GCCOPT) -g $(GCCWARN) -Wno-sign-compare
SFLAGS += $(CFLAGS) -D__ASSEMBLY__
LDFLAGS += -m elf_$(ARCH)

ifeq ($(CC),gcc)
SFLAGS += -Wa,--fatal-warning
endif

MBR_SRC := $(wildcard *.S)


all: $(MBR_SRC:%.S=%.bin) $(MBR_SRC:%.S=%_c.bin) $(MBR_SRC:%.S=%_f.bin)

%.o: %.S
	$(CC) $(MAKEDEPS) $(SFLAGS) -c -o $@ $<

%_c.o: %.S
	$(CC) $(MAKEDEPS) $(SFLAGS) -DCTRL_80 -c -o $@ $<

%_f.o: %.S
	$(CC) $(MAKEDEPS) $(SFLAGS) -DFORCE_80 -c -o $@ $<

%.elf: %.o mbr.ld
	$(LD) $(LDFLAGS) -T mbr.ld -e _start -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(CHMOD) -x $@

clean:
	rm -f *.o *.elf .*.d
	rm -f *.bin

test: all
	$(SHA1SUM) -c sha1sums.txt

.PHONY: all clean test
.PRECIOUS: %.elf %.o %_c.o %_f.o

-include .*.d
