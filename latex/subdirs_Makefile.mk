PANDOC ?= pandoc

include $(dir $(lastword $(MAKEFILE_LIST)))../common.mk

RSTFILES := $(wildcard *.rst)
TEXFILES := $(wildcard *.tex)
PDFS := $(TEXFILES:%.tex=%.pdf) $(RSTFILES:%.rst=%.pdf)

PANDOCFLAGS ?=
# Files in PANDOCFLAGS which have to be listed in the dependencies
PANDOCFLAGS_DEPS ?=

all: $(PDFS)
	@:

clean:
	$(CLEAN_CMD)

test: all
	@:

%.pdf: %.tex
	$(V_LATEXMK)$(LATEXMK) -pdf -interaction=batchmode -use-make $<

%.pdf: %.rst $(PANDOCFLAGS_DEPS)
	$(V_PANDOC)$(PANDOC) -s $(PANDOCFLAGS) -o $@ $<

# Produce LaTeX from Restructured Text in order to debug things
%.rst.tex: %.rst $(PANDOCFLAGS_DEPS)
	$(V_PANDOC)$(PANDOC) -s $(PANDOCFLAGS) -o $@ $<

.PHONY: all clean test
