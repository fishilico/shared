include ../../../env-python.mk

NEVER_TEST_BINARIES := enumerate_nsec.py enumerate_nsec3.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_CRYPTODOME := $(call can-run,$(PYTHON) -c 'import Cryptodome')

ifneq ($(HAVE_PYTHON_CRYPTODOME),y)
NONTEST_BINARIES += verify_dnssec.py
endif

BINARIES := $(wildcard *.py)
TEST_BINARIES := $(filter-out $(NONTEST_BINARIES), $(BINARIES))

all:
	@:

clean:
	$(CLEAN_CMD)
	$(RM) ./dns_cache/DNS_*.RRSIG_cache.txt

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

# Do not report scripts which have no chance to being tested in list-nobuild
list-nobuild:
	@echo $(sort $(filter-out $(NEVER_TEST_BINARIES), $(NONTEST_BINARIES)))

test: all
	@$(call run-test-progs,$(TEST_BINARIES))

sync-inet:
	$(PYTHON) verify_dnssec.py --update-tld-list --refresh --use-cloudflare --use-google

.PHONY: all clean lint list-nobuild test sync-inet

-include .*.d
