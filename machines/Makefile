include ../env-python.mk

# Python's pathlib module was introduced in Python 3.4
HAVE_PYTHON_PATHLIB := $(call can-run,$(PYTHON) -c 'import pathlib')

all:
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

# Download tags for Docker images
sync-inet:
	$(PYTHON) ./check_updates.py

test: all
ifeq ($(HAVE_PYTHON_PATHLIB), y)
	$(PYTHON) ./check_updates.py --no-net
else
	@:
endif

.PHONY: all clean lint sync-inet test
