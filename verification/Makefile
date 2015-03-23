include ../os-detect.mk

# Use FRAMAC=frama-c-gui to use the gui
FRAMAC ?= frama-c

# Use Frama-C libc headers which contains ACSL annotations.
FRAMAC_SHARE_PATH := $(shell $(FRAMAC) -print-share-path)
FRAMAC_CFLAGS := -nostdinc -I$(FRAMAC_SHARE_PATH)/libc -D__FRAMAC__
FRAMAC_TMPDIR := /tmp/frama-c-$(id -u)

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%.$(BIN_EXT))
FRAMAC_TARGETS := $(SOURCES:%.c=%.frama)

all: $(BINARIES)
	@:

all-frama: $(FRAMAC_TARGETS)

clean:
	$(CLEAN_CMD)

# In "make test", only test that the binaries actually run, don't actually verify them
test: all
	@for P in $(sort $(BINARIES)); do echo ./$$P && ./$$P || exit $$? ; done

%.$(BIN_EXT): .%.o
	$(V_CCLD)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# some files redefine C built-in functions strlen and memcpy
.%.o: CFLAGS += -fno-builtin

.%.o: %.c
	$(V_CC)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

%.frama: %.c
	[ -d '$(FRAMAC_TMPDIR)' ] || mkdir '$(FRAMAC_TMPDIR)'
	@# Examples of Frama-C parameters:
	@# - Value: -val -slevel 3
	@# - Weakest precondition: -wp -wp-rte -wp-model Typed+cast -wp-timeout 5 -wp-split -wp-out tmp -wp-fct main
	@# - Jessie: -jessie -jessie-atp=simplify -jessie-infer-annot pre
	$(V_FRAMAC)$(FRAMAC) -cpp-extra-args='$(FRAMAC_CFLAGS)' \
		-pp-annot -no-unicode \
		-wp -wp-rte -wp-model Typed+cast -wp-timeout 25 -wp-split -wp-out '$(FRAMAC_TMPDIR)' $^

# Run Frama-C GUI
%.frama-gui: FRAMAC := $(FRAMAC:%frama-c=%frama-c-gui)
%.frama-gui: %.frama
	@:

.PHONY: all all-frama clean test %.frama %.frama-gui
.PRECIOUS: .%.o

-include .*.d
