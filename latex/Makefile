PDFLATEX = pdflatex < /dev/null

TEXFILES := $(wildcard *.tex)
PDFS := $(TEXFILES:%.tex=%.pdf)

all: $(PDFS)

clean:
	rm -f *.aux *.log *.out *.pdf *.toc

test: all

# Compile 2 times each TeX file
%.pdf: %.tex
	$(PDFLATEX) $<
	$(PDFLATEX) $<

.PHONY: all clean test
