# Run every Makefile in subdirectories
SUBMAKEFILES := $(wildcard */Makefile)
SUBDIRS := $(SUBMAKEFILES:%/Makefile=%)
ALL_TARGETS := $(addprefix all\:, $(SUBDIRS))
CLEAN_TARGETS := $(addprefix clean\:, $(SUBDIRS))
TARGETS := $(ALL_TARGETS) $(CLEAN_TARGETS)

all: $(ALL_TARGETS)

clean: $(CLEAN_TARGETS)

$(TARGETS): TARGET = $(firstword $(subst :, ,$@))
$(TARGETS):
	$(MAKE) -C "$(@:$(TARGET):%=%)" $(TARGET)

.PHONY: all clean $(TARGETS)
