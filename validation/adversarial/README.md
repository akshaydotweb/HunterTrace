# Adversarial Validation Suite

This folder contains scripts and datasets for adversarial evaluation of the HunterTrace attribution engine.

## Contents
- `adversarial_dataset_generator.py` — Generates adversarial phishing samples for evaluation.
- `eval_harness.py` — Runs the Bayesian attribution engine on adversarial datasets and produces detailed metrics.
- `adv_dataset.json` — Default adversarial dataset (regenerate as needed).
- `adv_eval_results.json` — Evaluation results for the current adversarial dataset.
- `adv_large.json` — Large-scale adversarial dataset (1600 samples, 200 per scenario).
- `adv_compromised_relay.json` — Scenario-specific dataset for deep analysis.

## Typical Workflow

1. **Generate adversarial samples:**
   ```bash
   python adversarial_dataset_generator.py --count 800 --summary
   ```
   - Output: `adv_dataset.json`

2. **Evaluate against the engine:**
   ```bash
   PYTHONPATH=. python3 eval_harness.py --dataset adv_dataset.json --out adv_eval_results.json
   ```
   - Output: `adv_eval_results.json`

3. **Scale up for stress testing:**
   ```bash
   python adversarial_dataset_generator.py --count 1600 --out adv_large.json
   ```

4. **Isolate a scenario for deep analysis:**
   ```bash
   python adversarial_dataset_generator.py --scenario compromised_relay --count 200 --out adv_compromised_relay.json
   python eval_harness.py --dataset adv_compromised_relay.json --scenario compromised_relay --verbose
   ```

## Notes
- All outputs are written to this folder by default.
- Ensure you run with `PYTHONPATH=.` from the project root for correct imports.
- For structured reporting, see the main project README and docs.
