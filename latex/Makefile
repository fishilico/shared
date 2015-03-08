PDFLATEX = pdflatex -interaction batchmode > /dev/null

include ../common.mk

TEXFILES := $(wildcard *.tex)
PDFS := $(TEXFILES:%.tex=%.pdf)

all: $(PDFS)

clean:
	$(CLEAN_CMD)

test: all

# Compile 2 times each TeX file
%.pdf: %.tex
	$(V_PDFLATEX)($(PDFLATEX) $< && $(PDFLATEX) $<) || ($(RM) $@ && false)

.PHONY: all clean test
