LATEXMK ?= latexmk
MAIN := main.tex
OUTDIR := build

.PHONY: pdf clean distclean

pdf:
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error -outdir=$(OUTDIR) $(MAIN)

clean:
	$(LATEXMK) -c -outdir=$(OUTDIR) $(MAIN)

distclean:
	$(LATEXMK) -C -outdir=$(OUTDIR) $(MAIN)
	rm -rf $(OUTDIR)
