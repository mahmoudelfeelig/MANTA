# Thesis Paper (LaTeX)

This folder contains the thesis manuscript source (LaTeX).

## Related project docs
- `../README.md` - primary project overview, commands, and workflow notes.
- `../docs/features-checklist.md` - scope/completion checklist and remaining publication-readiness work.
- `../docs/licenses.md` - license and dataset compliance checklist.
- `../docs/references.md` - curated technical and academic references.

## Build
```bash
cd thesis-paper
make pdf
```

Output PDF is written to `thesis-paper/build/`.

## Structure
- `main.tex` - document entry point
- `metadata.tex` - title/author/supervisor placeholders
- `preamble.tex` - packages and macros
- `chapters/` - thesis chapters
- `appendices/` - appendices (reproducibility, extra tables, etc.)
- `bibliography/references.bib` - BibTeX references
- `figures/` - figures (tracked)
