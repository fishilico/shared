include ../../env-python.mk

all: file_dates.txt
	@:

clean:
	$(CLEAN_CMD)

lint:
	$(FLAKE8) $(FLAKE8_PARAMS) *.py
	$(MYPY) $(MYPY_PARAMS) *.py
	$(PYLINT) $(PYLINT_PARAMS) *.py

test: all
	@:

file_dates.txt: show_dates.sh $(wildcard *.db/*_versions.db.json)
	$(SH) show_dates.sh > file_dates.txt

.PHONY: all clean lint test
