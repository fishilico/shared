PDFLATEX = pdflatex < /dev/null
RM ?= rm -f

TEXFILES := $(wildcard *.tex)
PDFS := $(TEXFILES:%.tex=%.pdf)

all: $(PDFS)

clean:
	$(RM) *.aux *.log *.out *.pdf *.toc

test: all

# Compile 2 times each TeX file
%.pdf: %.tex
	$(PDFLATEX) $<
	$(PDFLATEX) $<

.PHONY: all clean test
