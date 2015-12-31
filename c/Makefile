PKG_CONFIG ?= pkg-config
SH ?= sh
WGET ?= wget

include ../os-detect.mk

SOURCES := $(wildcard *.c)
ALL_PROGRAMS := $(SOURCES:%.c=%)

# Programs which need specific options
GMP_PROGRAMS := gmp_functions
OPENMP_PROGRAMS := openmp_matrix
GTK_PROGRAMS := gtk_alpha_window
X86_PROGRAMS := $(filter x86-%, $(ALL_PROGRAMS))

# Programs not to test automatically, because they hang
NONTEST_PROGRAMS := gtk_alpha_window
NONTEST_BINARIES := $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)) x86-create_cpuid_enum_h.sh

# Find other programs. Only programs in $(PROGRAMS) are built.
PROGRAMS := $(filter-out \
	$(GMP_PROGRAMS) $(OPENMP_PROGRAMS) $(GTK_PROGRAMS) $(X86_PROGRAMS), \
	$(ALL_PROGRAMS))

# view_sizes.c uses "long long" type, so disable the related warning
view_sizes.o: CFLAGS += $(call cc-disable-warning,long-long)


# Only compile GMP programs when gmp.h can be found
HAVE_GMP := $(call ccpp-has-option,-include gmp.h)
ifeq ($(HAVE_GMP),y)
PROGRAMS += $(GMP_PROGRAMS)
endif
$(GMP_PROGRAMS:%=%.$(BIN_EXT)): LIBS += -lgmp

# When gcc is not compiled with pthread, -fopenmp makes the preprocessor fails
# clang 3.5.0 has partial support for OpenMP, omp.h is missing but gcc's omp.h
# can be used, and can even be set up in clang include files by copying
# /usr/lib/gcc/$(gcc -dumpmachine)/${GCC_VERSION}/include/omp.h to
# /usr/lib/clang/${CLANG_VERSION}/include/omp.h
HAVE_OPENMP := $(call ccpp-has-option,-fopenmp -include omp.h)
ifeq ($(HAVE_OPENMP),y)
PROGRAMS += $(OPENMP_PROGRAMS)
endif
$(OPENMP_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -fopenmp
$(OPENMP_PROGRAMS:%=.%.o): CFLAGS += -fopenmp $(call cc-disable-warning,source-uses-openmp)

# Only compile Gtk+ programs where $(CC) is not used for cross-compilation
ifeq ($(filter-out cc gcc clang, $(CC)),)
	HAVE_GTK3 := $(call can-run,$(PKG_CONFIG) --exists gtk+-3.0)
	ifeq ($(HAVE_GTK3),y)
		PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-3.0)
$(GTK_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-3.0) \
	$(call cc-disable-warning,pedantic) $(call cc-disable-warning,cast-qual)
	else
		HAVE_GTK2 := $(call can-run,$(PKG_CONFIG) --exists gtk+-2.0)
		ifeq ($(HAVE_GTK2),y)
			PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-2.0)
			# Gtk+2 headers:
			# * Use variadic macros (C99 feature)
			# * Use prototypes wihch are not strict
$(GTK_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-2.0) --std=c99 \
	$(call cc-disable-warning,strict-prototypes) $(call cc-disable-warning,cast-qual)
		endif
	endif
endif

# Use $(CC) -dumpmachine to find out the target triplet
TARGET_TRIPLET := $(shell $(CC) -dumpmachine)
ifneq (,$(findstring i386, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
else ifneq (,$(findstring i486, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
else ifneq (,$(findstring i686, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
else ifneq (,$(findstring x86_64, $(TARGET_TRIPLET)))
PROGRAMS += $(X86_PROGRAMS)
endif

TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PROGRAMS:%=%.$(BIN_EXT)) $(wildcard *.sh))

all: $(PROGRAMS:%=%.$(BIN_EXT))
	@:

clean:
	$(CLEAN_CMD)

list-nobuild:
	@echo $(filter-out $(PROGRAMS), $(ALL_PROGRAMS))

test: all
	@for P in $(sort $(TEST_BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

float_asm.$(BIN_EXT): LIBS += -lm
%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

x86-cpuid.o: x86-cpuid_enum.h
.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

update_cpuid: x86-linux-cpufeature.h.tmp x86-linux-cpu-scattered.c.tmp x86-create_cpuid_enum_h.sh
	$(SH) ./x86-create_cpuid_enum_h.sh > x86-cpuid_enum.h

LINUX_URL := https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain
x86-linux-cpufeature.h.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/include/asm/cpufeature.h' || (rm $@ ; false)

x86-linux-cpu-scattered.c.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/kernel/cpu/scattered.c' || (rm $@ ; false)

.PHONY: all clean list-nobuild test update_cpuid
.PRECIOUS: .%.o

-include .*.d
