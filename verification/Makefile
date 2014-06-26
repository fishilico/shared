CC ?= cc
# Use FRAMAC=frama-c-gui to use the gui
FRAMAC ?= frama-c

CPPFLAGS ?= -D_FORTIFY_SOURCE=2
CFLAGS ?= -O2 -Wall -W -Wextra -ansi -pedantic -pipe \
	-Wmissing-prototypes -Wno-unused-function -Wformat=2 -Wpointer-arith \
	-Winit-self -Wwrite-strings -Wno-shadow \
	-fno-exceptions -fno-stack-protector -fvisibility=hidden -fPIE
LDFLAGS ?= -Wl,-z,relro,-z,now,--no-undefined -fPIE -pie

# Use Frama-C libc headers which contains ACSL annotations.
FRAMAC_SHARE_PATH := $(shell frama-c -print-share-path)
FRAMAC_CFLAGS := -nostdinc -I$(FRAMAC_SHARE_PATH)/libc
FRAMAC_TMPDIR := /tmp/frama-c-$(id -u)

SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJECTS :=

OBJECTS := $(SOURCES:%.c=%.o)
BINARIES := $(OBJECTS:%.o=%.out)
FRAMAC_TARGETS := $(SOURCES:%.c=%.frama)

all: $(BINARIES)

all-frama: $(FRAMAC_TARGETS)

clean:
	rm -f *.o *.out

%.out: %.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

%.frama: %.c
	[ -d '$(FRAMAC_TMPDIR)' ] || mkdir '$(FRAMAC_TMPDIR)'
	@# Examples of Frama-C parameters:
	@# - Value: -val -slevel 3
	@# - Weakest precondition: -wp -wp-rte -wp-model Typed+cast -wp-timeout 5 -wp-split -wp-out tmp -wp-fct main
	@# - Jessie: -jessie -jessie-atp=simplify -jessie-infer-annot pre
	$(FRAMAC) -cpp-extra-args='$(FRAMAC_CFLAGS)' \
		-pp-annot -no-unicode \
		-wp -wp-rte -wp-model Typed+cast -wp-timeout 25 -wp-split -wp-out '$(FRAMAC_TMPDIR)' $<

.PHONY: all all-frama clean
