include ../../os-detect.mk

GREP ?= grep
UNAME ?= uname

# Find other programs. Only programs in $(PROGRAMS) are built.
SOURCES := $(wildcard *.c)
PROGRAMS := $(filter-out arch_% os_% test_asm_%, $(SOURCES:%.c=%))

# Add OS- and arch-dependent object files
TARGET_TRIPLET := $(get-cc-target-triplet)
TARGET_ARCH := $(or $(call cc-triplet2arch,$(TARGET_TRIPLET)),unknown)
TARGET_OS := $(or $(call cc-triplet2os,$(TARGET_TRIPLET)),unknown)

OBJECTS := .arch_common.o .arch_$(TARGET_ARCH).o .os_$(TARGET_OS).o
PROGRAMS += test_asm_$(TARGET_ARCH)
BINARIES := $(PROGRAMS:%=%.$(BIN_EXT))

ifeq ($(TARGET_ARCH),x86_64)
    ifeq ($(TARGET_OS),linux)
        # Disable EVEX support (cf. notes_x86_evex_avx512.md)
        HAVE_CPUINFO_EVEX := $(call can-run,$(GREP) '^flags.* avx512bw avx512vl' /proc/cpuinfo)
        ifeq ($(HAVE_CPUINFO_EVEX),y)
            RUN_TEST_PREFIX := echo SKIP because current CPU supports EVEX
        endif
    else ifeq ($(TARGET_OS),windows)
        # Recent versions of Windows also use AVX-512
        RUN_TEST_PREFIX := echo SKIP because Windows can support AVX-512
    endif
endif

all: $(BINARIES)
	@:

clean:
	$(CLEAN_CMD)

debug: CPPFLAGS += -DDEBUG=1
debug: all

test: all
	@$(call run-test-progs,$(BINARIES))

%.$(BIN_EXT): .%.o $(OBJECTS)
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Disable strict-aliasing warning for XMM sub-part tests
.test_%.o: CFLAGS += $(call cc-disable-warning,strict-aliasing)

.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.arch_unknown.o:
	@echo "Unknown architecture from triplet $(TARGET_TRIPLET)"
	@false

.os_unknown.o:
	@echo "Unknown OS from triplet $(TARGET_TRIPLET)"
	@false

.PHONY: all clean debug test
.PRECIOUS: .%.o

-include .*.d
