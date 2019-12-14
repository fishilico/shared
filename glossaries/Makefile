include ../env-python.mk

NEVER_TEST_BINARIES :=
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_FSTRINGS := $(call can-run,$(PYTHON) -c 'print(f"{repr(6*7)}")')

ifneq ($(HAVE_FSTRINGS),y)
NONTEST_BINARIES += check_sort_order.py
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

list-nobuild:
	@echo $(sort $(filter-out $(NEVER_TEST_BINARIES), $(NONTEST_BINARIES)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

.PHONY: all clean lint list-nobuild test
