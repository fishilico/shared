include ../common.mk

TEXFILES := $(wildcard *.tex)
PDFS := $(TEXFILES:%.tex=%.pdf)

all: $(PDFS)
	@:

clean:
	$(CLEAN_CMD)
	$(LATEXMK) -C

test: all
	@:

%.pdf: %.tex
	$(V_LATEXMK)$(LATEXMK) -pdf -interaction=batchmode -use-make $<

.PHONY: all clean test
