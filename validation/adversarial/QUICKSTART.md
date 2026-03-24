# HunterTrace Validation: Adversarial & Automation Quickstart

This guide summarizes the adversarial validation and automation pipeline for HunterTrace.

## 1. Generate Adversarial Samples

Generate 800 adversarial samples (all scenarios):
```bash
python adversarial_dataset_generator.py --count 800 --summary
```
- Output: `adv_dataset.json`

## 2. Evaluate Against the Engine

Run the evaluation harness on the generated dataset:
```bash
PYTHONPATH=. python3 eval_harness.py --dataset adv_dataset.json --out adv_eval_results.json
```
- Output: `adv_eval_results.json`

## 3. Scale Up for Stress Testing

Generate a larger dataset (1600 samples, 200 per scenario):
```bash
python adversarial_dataset_generator.py --count 1600 --out adv_large.json
```

## 4. Scenario-Specific Deep Analysis

Generate and evaluate only the `compromised_relay` scenario:
```bash
python adversarial_dataset_generator.py --scenario compromised_relay --count 200 --out adv_compromised_relay.json
python eval_harness.py --dataset adv_compromised_relay.json --scenario compromised_relay --verbose
```

## Notes
- All scripts and outputs are in this folder.
- Always run from the project root with `PYTHONPATH=.` for correct imports.
- For full documentation, see the main project README and `docs/`.
