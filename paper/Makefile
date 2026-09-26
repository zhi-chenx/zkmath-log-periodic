.PHONY: all tables pdf clean

all: tables pdf

tables:
	PYTHONDONTWRITEBYTECODE=1 python3 make_tables.py

pdf:
	latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex

clean:
	latexmk -C main.tex
