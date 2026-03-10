# MANTA Evidence Package

For thesis appendix or publication handoff, the evidence package should contain:
- experiment manifest
- privacy-view manifests
- model reports
- comparison matrices
- replay/soak reports
- performance reports
- screenshots or dashboard exports when relevant

Archive a run with:

```bash
python tools/archive_experiment_evidence.py \
  --input-dir ml-pipeline/experiment-runs/real-run-001 \
  --output-zip deliverables/manta-evidence-real-run-001.zip
```
