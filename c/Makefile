PKG_CONFIG ?= pkg-config
SH ?= sh
UNAME ?= uname
WGET ?= wget

include ../os-detect.mk

# Programs which need specific options
OPENMP_PROGRAMS := openmp_matrix
GTK_PROGRAMS := gtk_alpha_window

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(SOURCES:%.c=%)
PROGRAMS := $(filter-out $(OPENMP_PROGRAMS) $(GTK_PROGRAMS), $(ALL_PROGRAMS))

# view_sizes.c uses "long long" type, so disable the related warning
view_sizes.o: CFLAGS += -Wno-long-long

# when gcc is not compiled with pthread, -fopenmp makes the preprocessor fails
ifeq ($(shell $(CC) -Werror -fopenmp -E - < /dev/null > /dev/null 2>&1 && echo y), y)
PROGRAMS += $(OPENMP_PROGRAMS)
$(OPENMP_PROGRAMS:%=%$(BIN_EXT)): LDFLAGS += -fopenmp
$(OPENMP_PROGRAMS:%=%.o): CFLAGS += -fopenmp
endif

HAVE_GTK3 := $(shell $(PKG_CONFIG) --exists gtk+-3.0 2> /dev/null && echo 'y' || echo 'n')
ifeq ($(HAVE_GTK3), y)
	PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-3.0)
$(GTK_PROGRAMS:%=%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
else
	HAVE_GTK2 := $(shell $(PKG_CONFIG) --exists gtk+-2.0 2> /dev/null && echo 'y' || echo 'n')
	ifeq ($(HAVE_GTK2), y)
		PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-2.0)
$(GTK_PROGRAMS:%=%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-2.0)
	endif
endif

all: $(PROGRAMS:%=%$(BIN_EXT))

clean:
	rm -f *.o *.bin *.exe kernel-x86-*.[ch]

%$(BIN_EXT): %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

cpuid.o: cpuid_enum.h
%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

update_cpuid: kernel-x86-cpufeature.h kernel-x86-cpu-scattered.c create_cpuid_enum_h.sh
	$(SH) ./create_cpuid_enum_h.sh > cpuid_enum.h

LINUX_URL := https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain
kernel-x86-cpufeature.h:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/include/asm/cpufeature.h' || (rm $@ ; false)

kernel-x86-cpu-scattered.c:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/kernel/cpu/scattered.c' || (rm $@ ; false)

.PHONY: all clean update_cpuid
