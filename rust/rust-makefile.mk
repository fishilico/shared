# Makefile included in subdirectories in order to merge common cargo build commands
include $(dir $(lastword $(MAKEFILE_LIST)))../common.mk

all:
	$(V_CARGO_BUILD)$(CARGO) build

clean:
	$(CLEAN_CMD)
	$(V_CARGO_CLEAN)$(CARGO) clean

doc:
	$(CARGO) doc --document-private-items

fmt:
	$(CARGO) fmt

list-nobuild:
	@:

test: all
	@:

.PHONY: all clean doc fmt list-nobuild test
