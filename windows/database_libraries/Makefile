include ../../common.mk

all: file_dates.txt
	@:

clean:
	$(CLEAN_CMD)

test: all
	@:

file_dates.txt: show_dates.sh $(wildcard *.db/*_versions.db.json)
	$(SH) show_dates.sh > file_dates.txt

.PHONY: all clean test
