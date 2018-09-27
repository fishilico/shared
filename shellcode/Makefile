include ../os-detect.mk
include ../env-python.mk

CHMOD ?= chmod
GREP ?= grep
OBJCOPY ?= objcopy
OBJDUMP ?= objdump
SHA512SUM ?= sha512sum
UNAME ?= uname

# Find the system identifier to use
TARGET_TRIPLET := $(get-cc-target-triplet)
TARGET_ARCH := $(or $(call cc-triplet2arch,$(TARGET_TRIPLET)),unknown-arch)
TARGET_OS := $(or $(call cc-triplet2os,$(TARGET_TRIPLET)),unknown-OS)

SHELLCODE_NAME := $(TARGET_OS)_$(TARGET_ARCH)
SHELLCODE_BIN := $(SHELLCODE_NAME).$(BIN_EXT)
SHELLCODE_RAW := $(SHELLCODE_NAME).raw.out

ALL_TARGETS := $(SHELLCODE_RAW)
ifeq ($(TARGET_OS), linux)
	ALL_TARGETS += multiarch_linux.raw.out
endif

all: $(ALL_TARGETS)
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: all $(ALL_TARGETS:%.raw.out=%.$(BIN_EXT))
	@$(call run-test-progs,$(wildcard *.py))
ifeq ($(TARGET_OS), linux)
	@$(call run-test-progs,multiarch_linux.$(BIN_EXT))
	$(SHA512SUM) -c sha512sums.txt
endif

# Dump of the shellcode
shcdump: $(SHELLCODE_RAW) $(SHELLCODE_BIN)
	$(PYTHON) -c 'print(open("$(SHELLCODE_RAW)", "rb").read())'
	$(OBJDUMP) -d $(SHELLCODE_BIN)

%.raw.out: %.$(BIN_EXT)
	$(V_OBJCOPY)$(OBJCOPY) -j .shcode -O binary $< $@ && $(CHMOD) -x $@

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

.%.o: %.S
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: all clean lint test shcdump
.PRECIOUS: %.$(BIN_EXT) .%.o
