PYTHON3 ?= python3
# pep8 may be replaced by pycodestyle
PEP8 ?= pep8
PYLINT ?= pylint

PEP8_PARAMS := --max-line-length=120

PYLINT_PARAMS := --msg-template='L{line}: {msg_id}({symbol}) {msg}'
PYLINT_PARAMS += --max-line-length=120
PYLINT_PARAMS += --min-public-methods=1
PYLINT_PARAMS += --disable=duplicate-code
PYLINT_PARAMS += --disable=invalid-name
PYLINT_PARAMS += --disable=locally-disabled
PYLINT_PARAMS += --disable=too-many-lines

include ../common.mk

all:
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(PEP8) $(PEP8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: all
	@:

.PHONY: all clean lint test
