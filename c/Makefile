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
X86_32_PROGRAMS := x86-read_64b_regs_in_32b_mode
X86_ANY_PROGRAMS := $(filter-out $(X86_32_PROGRAMS), $(X86_PROGRAMS))

# Programs not to test automatically, because they hang or are tested an other way
NONTEST_PROGRAMS := antidebug gtk_alpha_window
NONTEST_BINARIES := $(NONTEST_PROGRAMS:%=%.$(BIN_EXT)) x86-create_cpuid_enum_h.sh

# Find other programs. Only programs in $(PROGRAMS) are built.
PROGRAMS := $(filter-out \
	$(GMP_PROGRAMS) $(OPENMP_PROGRAMS) $(GTK_PROGRAMS) $(X86_PROGRAMS), \
	$(ALL_PROGRAMS))

# view_sizes.c uses "long long" type, so disable the related warning
view_sizes.o: CFLAGS += $(call cc-disable-warning,long-long)


# Only compile GMP programs when gmp.h can be found and libgmp can be used
HAVE_GMP := $(call ccld-has-option,-include gmp.h -lgmp)
ifeq ($(HAVE_GMP),y)
PROGRAMS += $(GMP_PROGRAMS)
endif
$(GMP_PROGRAMS:%=%.$(BIN_EXT)): LIBS += -lgmp

# On some distributions (e.g. Sabayon with -m32), using OpenMP requires linking
# with libatomic. On others, libatomic is not available but OpenMP still works.
# In order to support both cases, find out whether libatomic is available.
HAVE_LIBATOMIC := $(call ccld-has-option,-latomic)
ifeq ($(HAVE_LIBATOMIC),y)
LIBATOMIC_LIBS := -latomic
else
LIBATOMIC_LIBS :=
endif

# When gcc is not compiled with pthread, -fopenmp makes the preprocessor fails
# clang 3.5.0 has partial support for OpenMP, omp.h is missing but gcc's omp.h
# can be used, and can even be set up in clang include files by copying
# /usr/lib/gcc/$(gcc -dumpmachine)/${GCC_VERSION}/include/omp.h to
# /usr/lib/clang/${CLANG_VERSION}/include/omp.h
# On Debian wheezy, clang (version 3.0) uses gcc's omp.h but does not support
# OpenMP pragmas nor library.  Therefore test the actual linking.
HAVE_OPENMP_CPP := $(call ccpp-has-option,-fopenmp -include omp.h)
HAVE_OPENMP_LD := $(call can-run-with-tmp,.test-openmp.tmp,echo "int main(void){return omp_get_thread_num();}" |$(CC) $(LDFLAGS) -Werror -fopenmp -include omp.h -x c -o".test-openmp.tmp" - $(LIBATOMIC_LIBS) && ./.test-openmp.tmp)
HAVE_OPENMP := $(if $(filter yy,$(HAVE_OPENMP_CPP)$(HAVE_OPENMP_LD)),y,n)
ifeq ($(HAVE_OPENMP),y)
PROGRAMS += $(OPENMP_PROGRAMS)
endif
$(OPENMP_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -fopenmp
$(OPENMP_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(LIBATOMIC_LIBS)
$(OPENMP_PROGRAMS:%=.%.o): CFLAGS += -fopenmp $(call cc-disable-warning,source-uses-openmp)

# Only compile Gtk+ programs where $(CC) is not used for cross-compilation
ifeq ($(filter-out cc gcc clang, $(CC)),)
	HAVE_GTK3 := $(call pkg-config-with-options,gtk+-3.0,-include gtk/gtk.h)
	ifeq ($(HAVE_GTK3),y)
		PROGRAMS += $(GTK_PROGRAMS)
$(GTK_PROGRAMS:%=%.$(BIN_EXT)): LIBS += $(shell $(PKG_CONFIG) --libs gtk+-3.0)
$(GTK_PROGRAMS:%=.%.o): CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-3.0) \
	$(call cc-disable-warning,pedantic) \
	$(call cc-disable-warning,cast-qual) \
	$(call cc-disable-warning,redundant-parens) \
	$(call cc-disable-warning,used-but-marked-unused)
	else
		HAVE_GTK2 := $(call pkg-config-with-options,gtk+-2.0,--std=c99 \
			$(call cc-disable-warning,strict-prototypes) $(call cc-disable-warning,cast-qual) -include gtk/gtk.h)
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
TARGET_ARCH := $(get-cc-target-arch)
ifneq ($(filter x86_%,$(TARGET_ARCH)),)
	PROGRAMS += $(X86_ANY_PROGRAMS)
	HAVE_X86_32 := $(call ccld-has-option,-m32)
	ifeq ($(HAVE_X86_32),y)
		PROGRAMS += $(X86_32_PROGRAMS)
	endif
endif
$(X86_32_PROGRAMS:%=%.$(BIN_EXT)): LDFLAGS += -m32
$(X86_32_PROGRAMS:%=.%.o): CFLAGS += -m32

TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(PROGRAMS:%=%.$(BIN_EXT)) $(wildcard *.sh))

all: $(PROGRAMS:%=%.$(BIN_EXT))
	@:

clean:
	$(CLEAN_CMD)

list-nobuild:
	@echo $(sort $(filter-out $(PROGRAMS), $(ALL_PROGRAMS)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

float_asm.$(BIN_EXT): LIBS += -lm
%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

x86-cpuid.o: x86-cpuid_enum.h
.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

sync-inet: update_cpuid
	@:

update_cpuid: x86-linux-cpufeatures.h.tmp x86-linux-cpu-scattered.c.tmp x86-create_cpuid_enum_h.sh
	$(SH) ./x86-create_cpuid_enum_h.sh > x86-cpuid_enum.h

LINUX_URL := https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain
x86-linux-cpufeatures.h.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/include/asm/cpufeatures.h' || (rm $@ ; false)

x86-linux-cpu-scattered.c.tmp:
	$(WGET) -q -O $@ '$(LINUX_URL)/arch/x86/kernel/cpu/scattered.c' || (rm $@ ; false)

.PHONY: all clean list-nobuild test sync-inet update_cpuid
.PRECIOUS: .%.o

-include .*.d
