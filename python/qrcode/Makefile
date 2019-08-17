include ../../env-python.mk

NEVER_TEST_BINARIES := zbar_decode.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_PIL := $(call can-run,$(PYTHON) -c 'import PIL')

ifneq ($(HAVE_PYTHON_PIL),y)
NONTEST_BINARIES += hello_qr_decode.py
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

.PHONY: all clean lint list-nobuild test

-include .*.d
