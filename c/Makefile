PKG_CONFIG ?= pkg-config
SH ?= sh
WGET ?= wget

include ../os-detect.mk

SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(SOURCES:%.c=%)

# Programs which need specific options
OPENMP_PROGRAMS := openmp_matrix
GTK_PROGRAMS := gtk_alpha_window
X86_PROGRAMS := $(filter x86-%, $(ALL_PROGRAMS))

# Programs not to test automatically, because they hang
NONTEST_PROGRAMS := gtk_alpha_window
NONTEST_BINARIES := $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)) x86-create_cpuid_enum_h.sh

# Find other programs. Only programs in $(PROGRAMS) are built.
PROGRAMS := $(filter-out $(OPENMP_PROGRAMS) $(GTK_PROGRAMS) $(X86_PROGRAMS), $(ALL_PROGRAMS))

# view_sizes.c uses "long long" type, so disable the related warning
view_sizes.o: CFLAGS += -Wno-long-long

# when gcc is not compiled with pthread, -fopenmp makes the preprocessor fails
# clang 3.5.0 has partial support for OpenMP, omp.h is missing
HAVE_OPENMP := $(shell $(CC) -Werror -fopenmp -include omp.h -E - < /dev/null > /dev/null 2>&1 && echo y || echo n)
ifeq ($(HAVE_OPENMP), y)
PROGRAMS += $(OPENMP_PROGRAMS)
$(OPENMP_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -fopenmp
$(OPENMP_PROGRAMS:%=.%.o): CFLAGS += -fopenmp
endif

# Only compile Gtk+ programs where $(CC) is not used for cross-compilation
ifeq ($(filter-out cc gcc clang, $(CC)),)
	HAVE_GTK3 := $(shell $(PKG_CONFIG) --exists gtk+-3.0 2> /dev/null && echo 'y' || echo 'n')
	ifeq ($(HAVE_GTK3), y)
		PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-3.0)
$(GTK_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
	else
		HAVE_GTK2 := $(shell $(PKG_CONFIG) --exists gtk+-2.0 2> /dev/null && echo 'y' || echo 'n')
		ifeq ($(HAVE_GTK2), y)
			PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-2.0)
$(GTK_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-2.0)
		endif
	endif
endif

# Use $(CC) -dumpmachine to find out the target triplet
TARGET_TRIPLET := $(shell $(CC) -dumpmachine)
ifneq (,$(findstring i386, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
else ifneq (,$(findstring i686, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
else ifneq (,$(findstring x86_64, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
endif

TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PROGRAMS:%=%.$(BIN_EXT)) $(wildcard *.sh))

all: $(PROGRAMS:%=%.$(BIN_EXT))

clean:
	$(CLEAN_CMD)

test: all
	@for P in $(sort $(TEST_BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

float_asm.$(BIN_EXT): LIBS += -lm
%.$(BIN_EXT): .%.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

x86-cpuid.o: x86-cpuid_enum.h
.%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

update_cpuid: x86-linux-cpufeature.h.tmp x86-linux-cpu-scattered.c.tmp x86-create_cpuid_enum_h.sh
	$(SH) ./x86-create_cpuid_enum_h.sh > x86-cpuid_enum.h

LINUX_URL := https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain
x86-linux-cpufeature.h.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/include/asm/cpufeature.h' || (rm $@ ; false)

x86-linux-cpu-scattered.c.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/kernel/cpu/scattered.c' || (rm $@ ; false)

.PHONY: all clean test update_cpuid
.PRECIOUS: .%.o
