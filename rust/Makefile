# Stub Makefile in order to clean things up when "cargo build" is run from the workspace
include $(dir $(lastword $(MAKEFILE_LIST)))../common.mk

all:
	@:

clean:
	$(V_CARGO_CLEAN)$(CARGO) clean
	$(CLEAN_CMD)

list-nobuild:
	@:

test: all
	@:

.PHONY: all clean list-nobuild test
