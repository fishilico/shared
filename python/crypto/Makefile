include ../../env-python.mk

# Programs not to test automatically
NEVER_TEST_BINARIES := find_rsa_pkcs1v15_modulus.py keepass_decode.py
NONTEST_BINARIES := $(NEVER_TEST_BINARIES)

HAVE_PYTHON_CRYPTODOME := $(call can-run,$(PYTHON) -c 'import Cryptodome')

# "enum" module was introduced in Python 3.4 and was backported with "pip install enum34"
HAVE_PYTHON_ENUM := $(call can-run,$(PYTHON) -c 'import enum')

# Type hints were introduced in Python 3.5, through https://peps.python.org/pep-0484/
HAVE_PYTHON_TYPES := $(call can-run,$(PYTHON) -c 'a:int=0')

# F-strings were introduced in Python 3.6, through https://peps.python.org/pep-0498/
HAVE_FSTRINGS := $(call can-run,$(PYTHON) -c 'print(f"{repr(6*7)}")')

ifneq ($(HAVE_PYTHON_CRYPTODOME),y)
NONTEST_BINARIES += chacha20_poly1305_tests.py dhparam_tests.py dsa_tests.py ec_tests.py parse_openssl_enc.py rsa_tests.py
endif

ifneq ($(HAVE_PYTHON_ENUM),y)
NONTEST_BINARIES += tpm_decode_bios_measurements.py tpm_ea_policy.py
endif

ifneq ($(HAVE_PYTHON_TYPES),y)
NONTEST_BINARIES += ipfs_hash.py
endif

ifneq ($(HAVE_FSTRINGS),y)
NONTEST_BINARIES += eth_functions_keccak.py
endif

ifneq ($(HAVE_PYTHON_CRYPTODOME)$(HAVE_FSTRINGS),yy)
NONTEST_BINARIES += bip32_seed_derivation.py starknet_curve.py
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
