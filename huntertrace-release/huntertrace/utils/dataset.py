#!/usr/bin/env python3
"""
HUNTЕRТRACE — DATASET CREATOR & LOADER
========================================

Solves Issue #2 (No Dataset Handling) from the evaluation audit.

Provides:
  • DatasetEntry   — ground-truth label container for one email
  • DatasetLoader  — load, validate, and split a corpus.json
  • DatasetCreator — interactive CLI to label .eml files and build a corpus
  • BatchEvaluator — run hunterTrace on every entry and return raw predictions

Corpus JSON Format (corpus.json)
─────────────────────────────────
{
  "metadata": {
    "version":     "1.0",
    "created_at":  "2025-01-01T00:00:00",
    "total_emails": 200,
    "label_schema": "ISO-3166-1 alpha-2 country codes"
  },
  "emails": [
    {
      "id":                "email_001",
      "file":              "samples/phish_001.eml",
      "ground_truth": {
        "country":         "NG",
        "country_name":    "Nigeria",
        "region":          "Africa",
        "tier":            3,
        "confidence":      "high",
        "notes":           "Confirmed from leaked X-Originating-IP",
        "labeled_by":      "analyst_1",
        "labeled_at":      "2025-01-10T14:00:00"
      },
      "metadata": {
        "campaign":        "BEC_2024_Q4",
        "has_vpn":         true,
        "has_tor":         false,
        "webmail_type":    "gmail"
      }
    }
  ]
}

Usage
─────
    # Load existing corpus
    from dataset_creator import DatasetLoader
    dataset = DatasetLoader("dataset/corpus.json")
    train, test = dataset.split(test_ratio=0.20, seed=42)

    # Run batch evaluation
    from dataset_creator import BatchEvaluator
    evaluator = BatchEvaluator(pipeline_fn=my_pipeline_fn)
    predictions = evaluator.run(dataset.emails)

    # Create new corpus interactively
    from dataset_creator import DatasetCreator
    creator = DatasetCreator(output_path="dataset/corpus.json")
    creator.label_directory("samples/phishing_emails/")
"""

import json
import random
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Tuple, Callable, Any
from datetime import datetime
from collections import Counter


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GroundTruth:
    """Human-verified label for one email."""
    country:      str              # ISO-3166-1 alpha-2 (e.g. "NG")
    country_name: str              # Full name (e.g. "Nigeria")
    region:       str              # Continent/macro-region (e.g. "Africa")
    tier:         int              # 0–4 expected attribution tier
    confidence:   str = "medium"  # "high" | "medium" | "low" — analyst certainty
    notes:        str = ""
    labeled_by:   str = "analyst"
    labeled_at:   str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class EmailEntry:
    """Single entry in the evaluation corpus."""
    id:           str
    file:         str              # Relative path to .eml file
    ground_truth: GroundTruth
    metadata:     Dict[str, Any] = field(default_factory=dict)

    def exists(self, base_dir: str = ".") -> bool:
        return Path(base_dir, self.file).exists()


@dataclass
class Prediction:
    """Prediction from hunterTrace for one email."""
    email_id:       str
    file:           str
    predicted_country: Optional[str]    # ISO-3166-1 alpha-2
    predicted_region:  Optional[str]
    predicted_tier:    int
    confidence_score:  float            # 0.0–1.0
    aci_score:         float            # ACI
    signals_used:      int
    error:             Optional[str] = None   # Exception if pipeline failed
    raw_result:        Any             = None  # Full pipeline result object


# ─────────────────────────────────────────────────────────────────────────────
#  DATASET LOADER
# ─────────────────────────────────────────────────────────────────────────────

class DatasetLoader:
    """
    Load and validate a corpus.json file.

    Attributes
    ----------
    emails      : full list of EmailEntry objects
    metadata    : dict from the corpus "metadata" block
    """

    def __init__(self, corpus_path: str, base_dir: str = "."):
        self.corpus_path = Path(corpus_path)
        self.base_dir    = base_dir
        self.metadata: Dict[str, Any] = {}
        self.emails:   List[EmailEntry] = []
        self._load()

    # ── Loading ──────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.corpus_path.exists():
            raise FileNotFoundError(f"Corpus not found: {self.corpus_path}")

        with open(self.corpus_path) as f:
            raw = json.load(f)

        self.metadata = raw.get("metadata", {})
        raw_emails    = raw.get("emails", [])

        self.emails = []
        for item in raw_emails:
            gt_raw = item.get("ground_truth", {})
            gt = GroundTruth(
                country      = gt_raw.get("country", "??"),
                country_name = gt_raw.get("country_name", "Unknown"),
                region       = gt_raw.get("region", "Unknown"),
                tier         = int(gt_raw.get("tier", 0)),
                confidence   = gt_raw.get("confidence", "medium"),
                notes        = gt_raw.get("notes", ""),
                labeled_by   = gt_raw.get("labeled_by", "analyst"),
                labeled_at   = gt_raw.get("labeled_at", ""),
            )
            entry = EmailEntry(
                id           = item.get("id", f"email_{len(self.emails):04d}"),
                file         = item.get("file", ""),
                ground_truth = gt,
                metadata     = item.get("metadata", {}),
            )
            self.emails.append(entry)

        print(f"[DatasetLoader] Loaded {len(self.emails)} emails from {self.corpus_path}")

    # ── Filtering ─────────────────────────────────────────────────────────────

    def filter_by_confidence(self, confidence: str) -> List[EmailEntry]:
        """Return entries where analyst confidence matches ('high'|'medium'|'low')."""
        return [e for e in self.emails if e.ground_truth.confidence == confidence]

    def filter_by_country(self, country_code: str) -> List[EmailEntry]:
        return [e for e in self.emails if e.ground_truth.country == country_code]

    def filter_existing_files(self) -> List[EmailEntry]:
        """Return only entries whose .eml file exists on disk."""
        found = [e for e in self.emails if e.exists(self.base_dir)]
        missing = len(self.emails) - len(found)
        if missing:
            print(f"[DatasetLoader] WARNING: {missing} .eml files not found on disk.")
        return found

    # ── Splitting ─────────────────────────────────────────────────────────────

    def split(
        self,
        test_ratio: float = 0.20,
        seed:       int   = 42,
        stratify:   bool  = True,
    ) -> Tuple[List[EmailEntry], List[EmailEntry]]:
        """
        Train/test split with optional stratification by country.

        Parameters
        ----------
        test_ratio  : fraction of corpus for test set (default 0.20 = 20%)
        seed        : random seed for reproducibility
        stratify    : if True, maintain country distribution in both splits

        Returns
        -------
        (train_emails, test_emails)
        """
        rng = random.Random(seed)

        if not stratify:
            shuffled = list(self.emails)
            rng.shuffle(shuffled)
            n_test = max(1, int(len(shuffled) * test_ratio))
            return shuffled[n_test:], shuffled[:n_test]

        # Stratified split — group by country
        by_country: Dict[str, List[EmailEntry]] = {}
        for e in self.emails:
            by_country.setdefault(e.ground_truth.country, []).append(e)

        train, test = [], []
        for country, entries in by_country.items():
            rng.shuffle(entries)
            n_test = max(1, int(len(entries) * test_ratio))
            test.extend(entries[:n_test])
            train.extend(entries[n_test:])

        rng.shuffle(train)
        rng.shuffle(test)

        print(f"[DatasetLoader] Split: {len(train)} train / {len(test)} test "
              f"({len(by_country)} countries represented in test)")
        return train, test

    def k_fold_splits(
        self,
        k:    int = 5,
        seed: int = 42,
    ) -> List[Tuple[List[EmailEntry], List[EmailEntry]]]:
        """
        Return k (train, val) splits for cross-validation.
        Each fold has 1/k of the data as validation.
        """
        rng   = random.Random(seed)
        items = list(self.emails)
        rng.shuffle(items)

        fold_size = len(items) // k
        folds = []
        for i in range(k):
            val_start = i * fold_size
            val_end   = val_start + fold_size if i < k - 1 else len(items)
            val   = items[val_start:val_end]
            train = items[:val_start] + items[val_end:]
            folds.append((train, val))

        print(f"[DatasetLoader] Created {k}-fold CV splits "
              f"(~{fold_size} emails per fold)")
        return folds

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics about the corpus."""
        country_dist = Counter(e.ground_truth.country for e in self.emails)
        tier_dist    = Counter(e.ground_truth.tier    for e in self.emails)
        vpn_count    = sum(1 for e in self.emails if e.metadata.get("has_vpn"))
        tor_count    = sum(1 for e in self.emails if e.metadata.get("has_tor"))

        return {
            "total":          len(self.emails),
            "countries":      len(country_dist),
            "country_dist":   dict(country_dist.most_common(10)),
            "tier_dist":      dict(sorted(tier_dist.items())),
            "has_vpn":        vpn_count,
            "has_tor":        tor_count,
            "confidence_dist": dict(Counter(e.ground_truth.confidence for e in self.emails)),
        }

    def print_stats(self) -> None:
        s = self.stats()
        print("\n" + "=" * 60)
        print("CORPUS STATISTICS")
        print("=" * 60)
        print(f"  Total emails   : {s['total']}")
        print(f"  Countries      : {s['countries']}")
        print(f"  With VPN       : {s['has_vpn']} ({s['has_vpn']/max(s['total'],1):.0%})")
        print(f"  With Tor       : {s['has_tor']} ({s['has_tor']/max(s['total'],1):.0%})")
        print("\n  Tier distribution:")
        for tier, count in sorted(s["tier_dist"].items()):
            bar = "█" * int(count / max(s["total"], 1) * 30)
            print(f"    Tier {tier}: {bar} {count}")
        print("\n  Top countries:")
        for cc, count in list(s["country_dist"].items())[:8]:
            print(f"    {cc}: {count}")
        print("=" * 60 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  BATCH EVALUATOR
# ─────────────────────────────────────────────────────────────────────────────

class BatchEvaluator:
    """
    Run hunterTrace on a list of EmailEntry objects and collect Prediction results.

    Parameters
    ----------
    pipeline_fn : callable that takes a file path (str) and returns a
                  CompletePipelineResult from hunterTrace.
                  Signature: pipeline_fn(eml_path: str) -> CompletePipelineResult
    geo_country_fn : optional callable to extract country ISO code from
                     CompletePipelineResult. Defaults to standard field path.
    """

    def __init__(
        self,
        pipeline_fn:     Callable[[str], Any],
        geo_country_fn:  Optional[Callable[[Any], Optional[str]]] = None,
        base_dir:        str = ".",
        verbose:         bool = True,
    ):
        self.pipeline_fn    = pipeline_fn
        self.geo_country_fn = geo_country_fn or self._default_country_extractor
        self.base_dir       = base_dir
        self.verbose        = verbose

    @staticmethod
    def _default_country_extractor(result: Any) -> Optional[str]:
        """
        Extract predicted country from a CompletePipelineResult.
        Tries attribution result first, then geolocation.
        """
        # v3 attribution result
        attr = getattr(result, "attribution_result", None)
        if attr:
            region = getattr(attr, "primary_region", None)
            if region:
                return region  # Country name — caller may need ISO conversion

        # Direct geolocation
        geo_results = getattr(result, "geolocation_results", None) or {}
        for ip, geo in geo_results.items():
            country = getattr(geo, "country", None)
            if country:
                return country

        return None

    def run(
        self,
        entries:   List[EmailEntry],
        show_progress: bool = True,
    ) -> List[Prediction]:
        """
        Process each entry through the pipeline and return Prediction objects.

        Parameters
        ----------
        entries        : list of EmailEntry to evaluate
        show_progress  : print progress every 10 emails

        Returns
        -------
        list of Prediction (one per entry, including failed ones)
        """
        predictions: List[Prediction] = []
        n = len(entries)

        for i, entry in enumerate(entries):
            if show_progress and (i % 10 == 0 or i == n - 1):
                print(f"  [{i+1}/{n}] Processing {entry.id}...")

            eml_path = str(Path(self.base_dir, entry.file))
            pred = self._run_one(entry, eml_path)
            predictions.append(pred)

        n_ok  = sum(1 for p in predictions if p.error is None)
        n_err = n - n_ok
        print(f"\n[BatchEvaluator] Done: {n_ok} succeeded, {n_err} failed")
        return predictions

    def _run_one(self, entry: EmailEntry, eml_path: str) -> Prediction:
        try:
            result = self.pipeline_fn(eml_path)

            # Extract predicted country
            pred_country = self.geo_country_fn(result)

            # Extract region from attribution
            attr = getattr(result, "attribution_result", None)
            pred_region = None
            pred_tier   = 0
            conf_score  = 0.0
            aci_score   = 0.0
            signals_used = 0

            if attr:
                pred_region  = getattr(attr, "primary_region",     None)
                pred_tier    = getattr(attr, "tier",               0)
                conf_score   = getattr(attr, "aci_adjusted_prob",  0.0)
                aci_val      = getattr(attr, "aci",                None)
                aci_score    = getattr(aci_val, "final_aci", 0.0) if aci_val else 0.0
                signals_used = getattr(attr, "signals_used",       0)
                if isinstance(signals_used, (list, set)):
                    signals_used = len(signals_used)

            return Prediction(
                email_id          = entry.id,
                file              = entry.file,
                predicted_country = pred_country,
                predicted_region  = pred_region,
                predicted_tier    = pred_tier,
                confidence_score  = conf_score,
                aci_score         = aci_score,
                signals_used      = signals_used,
                raw_result        = result,
            )

        except Exception as exc:
            if self.verbose:
                print(f"    [!] {entry.id} failed: {exc}")
            return Prediction(
                email_id          = entry.id,
                file              = entry.file,
                predicted_country = None,
                predicted_region  = None,
                predicted_tier    = 0,
                confidence_score  = 0.0,
                aci_score         = 0.0,
                signals_used      = 0,
                error             = str(exc),
            )


# ─────────────────────────────────────────────────────────────────────────────
#  DATASET CREATOR (INTERACTIVE LABELER)
# ─────────────────────────────────────────────────────────────────────────────

class DatasetCreator:
    """
    Interactive CLI tool to label .eml files and build a corpus.json.

    Supports incremental labeling — resume where you left off if the output
    file already exists.

    Usage
    -----
        creator = DatasetCreator(output_path="dataset/corpus.json")
        creator.label_directory("samples/phishing_emails/")
    """

    # ISO 3166-1 alpha-2 → country name (common phishing source countries)
    COMMON_COUNTRIES = {
        "NG": "Nigeria",   "IN": "India",    "RU": "Russia",
        "CN": "China",     "US": "United States", "RO": "Romania",
        "BR": "Brazil",    "UA": "Ukraine",  "ZA": "South Africa",
        "GH": "Ghana",     "PK": "Pakistan", "ID": "Indonesia",
        "VN": "Vietnam",   "PH": "Philippines", "TR": "Turkey",
        "IR": "Iran",      "BG": "Bulgaria", "KP": "North Korea",
        "BY": "Belarus",   "XX": "Unknown",
    }

    REGION_MAP = {
        "NG": "Africa",    "GH": "Africa",  "ZA": "Africa",
        "IN": "Asia",      "PK": "Asia",    "ID": "Asia",
        "VN": "Asia",      "PH": "Asia",    "CN": "Asia",
        "IR": "Asia",      "KP": "Asia",    "TR": "Asia",
        "RU": "Europe",    "UA": "Europe",  "RO": "Europe",
        "BG": "Europe",    "BY": "Europe",
        "US": "Americas",  "BR": "Americas",
        "XX": "Unknown",
    }

    def __init__(self, output_path: str = "dataset/corpus.json"):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: List[Dict] = []
        self._labeled_ids: set   = set()

        # Resume from existing file if present
        if self.output_path.exists():
            with open(self.output_path) as f:
                existing = json.load(f)
            self._entries = existing.get("emails", [])
            self._labeled_ids = {e["id"] for e in self._entries}
            print(f"[DatasetCreator] Resuming — {len(self._entries)} already labeled")

    def label_directory(self, email_dir: str, file_ext: str = ".eml") -> None:
        """
        Scan directory for .eml files and label each one interactively.
        Files already in the corpus are skipped.
        """
        eml_files = sorted(Path(email_dir).rglob(f"*{file_ext}"))
        pending   = [f for f in eml_files
                     if f.stem not in self._labeled_ids
                     and str(f) not in self._labeled_ids]

        print(f"\n[DatasetCreator] Found {len(eml_files)} files, "
              f"{len(pending)} unlabeled.\n")

        for eml in pending:
            self._label_one(eml, email_dir)

        self._save()
        print(f"\n[DatasetCreator] Corpus saved: {self.output_path} "
              f"({len(self._entries)} entries)")

    def _label_one(self, eml_path: Path, base_dir: str) -> None:
        """Prompt analyst to label a single .eml file."""
        print("─" * 60)
        print(f"File: {eml_path.name}")

        # Show country options
        print("\nCommon origin countries:")
        for code, name in list(self.COMMON_COUNTRIES.items())[:10]:
            print(f"  {code} = {name}")
        print("  (Enter any ISO-3166-1 code for others)")

        country = input("\nOrigin country code: ").strip().upper() or "XX"
        country_name = self.COMMON_COUNTRIES.get(country, input("Country name: ").strip())
        region       = self.REGION_MAP.get(country, input("Region (e.g. Africa): ").strip())
        tier         = int(input("Expected tier (0-4): ").strip() or "2")
        confidence   = input("Confidence (high/medium/low) [medium]: ").strip() or "medium"
        has_vpn      = input("VPN detected? (y/n) [n]: ").strip().lower() == "y"
        has_tor      = input("Tor detected? (y/n) [n]: ").strip().lower() == "y"
        webmail      = input("Webmail type (gmail/yahoo/outlook/other/none) [none]: ").strip() or "none"
        campaign     = input("Campaign label (optional): ").strip()
        notes        = input("Notes (optional): ").strip()

        entry_id = eml_path.stem
        rel_path = str(eml_path.relative_to(base_dir))

        self._entries.append({
            "id":   entry_id,
            "file": rel_path,
            "ground_truth": {
                "country":      country,
                "country_name": country_name,
                "region":       region,
                "tier":         tier,
                "confidence":   confidence,
                "notes":        notes,
                "labeled_by":   os.environ.get("USER", "analyst"),
                "labeled_at":   datetime.now().isoformat(),
            },
            "metadata": {
                "campaign":    campaign,
                "has_vpn":     has_vpn,
                "has_tor":     has_tor,
                "webmail_type": webmail,
            }
        })
        self._labeled_ids.add(entry_id)

        # Auto-save every 10 entries to prevent data loss
        if len(self._entries) % 10 == 0:
            self._save(silent=True)
            print("  [auto-saved]")

    def _save(self, silent: bool = False) -> None:
        corpus = {
            "metadata": {
                "version":       "1.0",
                "created_at":    datetime.now().isoformat(),
                "total_emails":  len(self._entries),
                "label_schema":  "ISO-3166-1 alpha-2 country codes",
            },
            "emails": self._entries,
        }
        with open(self.output_path, "w") as f:
            json.dump(corpus, f, indent=2)
        if not silent:
            print(f"[DatasetCreator] Saved {len(self._entries)} entries → {self.output_path}")

    @staticmethod
    def create_sample_corpus(output_path: str = "dataset/sample_corpus.json", n: int = 10) -> None:
        """
        Generate a synthetic sample corpus.json for testing.
        Useful for verifying the evaluation framework without real emails.

        Parameters
        ----------
        output_path : where to write the sample corpus
        n           : number of synthetic entries to create
        """
        sample_countries = [
            ("NG", "Nigeria",    "Africa",  3),
            ("IN", "India",      "Asia",    2),
            ("RU", "Russia",     "Europe",  2),
            ("CN", "China",      "Asia",    1),
            ("RO", "Romania",    "Europe",  3),
            ("BR", "Brazil",     "Americas",2),
            ("UA", "Ukraine",    "Europe",  3),
            ("GH", "Ghana",      "Africa",  2),
            ("PK", "Pakistan",   "Asia",    1),
            ("VN", "Vietnam",    "Asia",    2),
        ]

        emails = []
        for i in range(n):
            cc, name, region, tier = sample_countries[i % len(sample_countries)]
            emails.append({
                "id":   f"email_{i+1:04d}",
                "file": f"samples/phish_{i+1:04d}.eml",
                "ground_truth": {
                    "country":      cc,
                    "country_name": name,
                    "region":       region,
                    "tier":         tier,
                    "confidence":   "high",
                    "notes":        "Synthetic sample",
                    "labeled_by":   "system",
                    "labeled_at":   datetime.now().isoformat(),
                },
                "metadata": {
                    "campaign":    f"CAMPAIGN_{chr(65 + i % 5)}",
                    "has_vpn":     i % 3 == 0,
                    "has_tor":     i % 7 == 0,
                    "webmail_type": ["gmail", "yahoo", "outlook", "none"][i % 4],
                }
            })

        corpus = {
            "metadata": {
                "version":       "1.0",
                "created_at":    datetime.now().isoformat(),
                "total_emails":  n,
                "label_schema":  "ISO-3166-1 alpha-2 — synthetic sample for testing",
            },
            "emails": emails,
        }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(corpus, f, indent=2)
        print(f"[DatasetCreator] Sample corpus ({n} entries) → {out}")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="HunterTrace Dataset Creator & Loader"
    )
    sub = parser.add_subparsers(dest="cmd")

    # Create sample corpus
    sample_p = sub.add_parser("sample", help="Generate a sample corpus.json")
    sample_p.add_argument("--output", default="dataset/sample_corpus.json")
    sample_p.add_argument("--n",      type=int, default=20)

    # Label directory
    label_p = sub.add_parser("label", help="Interactively label .eml files")
    label_p.add_argument("email_dir", help="Directory containing .eml files")
    label_p.add_argument("--output",  default="dataset/corpus.json")

    # Show stats
    stats_p = sub.add_parser("stats", help="Print corpus statistics")
    stats_p.add_argument("corpus", help="Path to corpus.json")

    args = parser.parse_args()

    if args.cmd == "sample":
        DatasetCreator.create_sample_corpus(args.output, args.n)

    elif args.cmd == "label":
        creator = DatasetCreator(output_path=args.output)
        creator.label_directory(args.email_dir)

    elif args.cmd == "stats":
        loader = DatasetLoader(args.corpus)
        loader.print_stats()

    else:
        parser.print_help()