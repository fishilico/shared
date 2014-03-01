# Run every Makefile in subdirectories
SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(SUBMAKEFILES:/Makefile=)

all: $(addprefix all.., $(SUBDIRS))

all..%: %
	$(MAKE) -C "$<" all

clean: $(addprefix clean.., $(SUBDIRS))

clean..%: %
	$(MAKE) -C "$<" clean

.PHONY: all clean
