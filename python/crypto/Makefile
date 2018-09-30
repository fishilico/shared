include ../../env-python.mk

# Programs not to test automatically
NEVER_TEST_BINARIES := find_rsa_pkcs1v15_modulus.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_CRYPTO := $(call can-run,$(PYTHON) -c 'import Crypto')

ifneq ($(HAVE_PYTHON_CRYPTO),y)
NONTEST_BINARIES += chacha20_poly1350_tests.py dsa_tests.py ec_tests.py rsa_tests.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))

# Lines with URLs should not be truncated
FLAKE8_PARAMS += --max-line-length=256


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
