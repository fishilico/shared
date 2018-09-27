include ../env-python.mk

PYLINT_PARAMS += --min-public-methods=1
PYLINT_PARAMS += --disable=duplicate-code
PYLINT_PARAMS += --disable=invalid-name
PYLINT_PARAMS += --disable=locally-disabled
PYLINT_PARAMS += --disable=too-many-lines

all:
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: all
	@:

.PHONY: all clean lint test
