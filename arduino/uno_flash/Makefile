OBJCOPY ?= objcopy
PYTHON3 ?= python3
# Use current python binary instead of system default for coverage
COVERAGE ?= $(PYTHON3) $(shell which coverage)

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

include ../../common.mk

all: initialflash.bin

clean:
	$(CLEAN_CMD)

initialflash.bin: initialflash.hex
	$(V_OBJCOPY)$(OBJCOPY) -I ihex -O binary $< $@

coverage:
	$(COVERAGE) erase
	$(COVERAGE) run "--include=./*.py" --branch decode_firmata.py > /dev/null
	$(COVERAGE) run "--include=./*.py" --branch decode_optiboot.py > /dev/null
	$(COVERAGE) report "--include=./*.py"
	$(COVERAGE) html "--include=./*.py"

lint:
	$(PEP8) $(PEP8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: all
	$(PYTHON3) ./decode_optiboot.py > optiboot.lst.txt
	$(PYTHON3) ./decode_firmata.py > firmata.lst.txt

.PHONY: all clean coverage lint test
