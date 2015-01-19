PAPER=results

all: results

results:
	pdflatex $(PAPER)
	-bibtex $(PAPER)
	pdflatex $(PAPER)
	pdflatex $(PAPER)

clean: 
	rm -rf *~ *.log *.aux *.bbl *.blg $(PAPER).pdf $(PAPER).ps *.dvi *.bcf *.run.xml
