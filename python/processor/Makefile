include ../../env-python.mk

NEVER_TEST_BINARIES := sync_chipsec_definitions.py sync_intel_microcode.py sync_linux_definitions.py sync_perfmon_definitions.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_FSTRING := $(call can-run,$(PYTHON) -c 'f""')

ifneq ($(HAVE_PYTHON_FSTRING),y)
NONTEST_BINARIES += x86_msr.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))


all:
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

# Do not report scripts which have no chance to being tested in list-nobuild
list-nobuild:
	@echo $(sort $(filter-out $(NEVER_TEST_BINARIES), $(NONTEST_BINARIES)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

sync-inet:
	$(PYTHON3) sync_chipsec_definitions.py
	$(PYTHON3) sync_intel_microcode.py -w
	$(PYTHON3) sync_linux_definitions.py
	$(PYTHON3) sync_perfmon_definitions.py

.PHONY: all clean lint list-nobuild test sync-inet

-include .*.d
