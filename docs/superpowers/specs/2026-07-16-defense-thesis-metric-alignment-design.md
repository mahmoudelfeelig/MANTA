# Defense thesis metric alignment

## Objective

Make `presentation/defense.pptx` consistent with the already-submitted thesis. The submitted thesis is authoritative; no newer, older, or alternative evaluation results will replace its reported values.

## Scope

- Audit every numerical result and associated interpretation in the defense deck against `thesis-paper/chapters/05-evaluation.tex`, `thesis-paper/chapters/07-conclusion.tex`, and the thesis-aligned report artifacts.
- Correct only values, labels, or nearby explanatory text that conflict with the thesis.
- Preserve the existing slide order, visual design, typography, spacing, and narrative.
- Do not change `presentation/demo.pptx` or `presentation/poster.pptx`.

## Authoritative values

The principal detection values are High-recall RF F1 0.925, Privacy RF F1 0.910, Adaptive hybrid RF F1 0.895 with FPR 0.043, backend boosted-tree F1 0.888, and Low-FPR RF F1 0.817 with FPR 0.024. Release app-ID leakage is 0.282, 0.151, and 0.135 for off, medium, and strict views. Corresponding utility F1 is 0.776, 0.685, and 0.653. Observer normalized leakage is 0.544 for app ID, 0.783 for app family, and 0.981 for dataset source. Hashing comparisons must use the values reported in the submitted thesis.

## Editing approach

Use the existing deck as the sole visual template. Import and edit inherited objects only. If a value is already correct, leave the object unchanged. Any replacement text must retain the current hierarchy and fit within the existing frame without reducing readability.

## Verification

Extract the final slide text and compare all numerical claims with the thesis sources. Render every slide, inspect the contact sheet and relevant full-size slides, and resolve any unintended wrapping, clipping, overlap, or footer inconsistency before delivery.
