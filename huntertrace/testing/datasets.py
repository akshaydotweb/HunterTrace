"""Real dataset ingestion and indexing.

Loads and indexes existing datasets from the mails/ directory including:
- CEAS 2008 challenge dataset (39K files)
- Fraud/phishing CSV datasets
- Auto-labeled corpus with ground truth
- Actor-based labeled samples
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DatasetSample:
    """Reference to a single test sample."""

    path: str  # File path (or in-memory indicator)
    category: str  # Dataset name (ceas, fraud, corpus, actor, etc.)
    metadata: dict = field(default_factory=dict)  # {label, confidence, ip, country, ...}
    ground_truth: Optional[dict] = None  # {region, country, ...} if available
    content: Optional[str] = None  # In-memory content for CSV-sourced samples


class DatasetLoader:
    """Load existing datasets from mails/ directory."""

    # Mails directory root
    MAILS_ROOT = Path(__file__).parent.parent.parent / "mails"

    @staticmethod
    def load_ceas(sample_limit: Optional[int] = None) -> list[DatasetSample]:
        """Load CEAS 2008 dataset from .eml files.

        Args:
            sample_limit: Max samples to load (None = all)

        Returns:
            List of DatasetSample objects with category='ceas'
        """
        ceas_dir = DatasetLoader.MAILS_ROOT / "ceas08_eml"
        samples = []

        if not ceas_dir.exists():
            return []

        eml_files = sorted(ceas_dir.glob("email_*.eml"))[:sample_limit]

        for eml_file in eml_files:
            try:
                content = eml_file.read_text(encoding="utf-8", errors="ignore")
                samples.append(
                    DatasetSample(
                        path=str(eml_file),
                        category="ceas",
                        metadata={"source": "CEAS 2008 Challenge", "file": eml_file.name},
                        ground_truth=None,  # CEAS has no ground truth labels
                        content=content,
                    )
                )
            except OSError:
                # Skip files that can't be read
                pass

        return samples

    @staticmethod
    def load_fraud_csv(
        csv_path: Optional[str] = None, sample_limit: Optional[int] = None
    ) -> list[DatasetSample]:
        """Load fraud dataset from CSV.

        Supports Nigerian_Fraud.csv, Nazario_5.csv, etc.

        Args:
            csv_path: Path to CSV file (auto-finds if None)
            sample_limit: Max samples to load (None = all)

        Returns:
            List of DatasetSample objects with category='fraud'
        """
        if csv_path is None:
            # Find fraud CSV files
            downloads_dir = DatasetLoader.MAILS_ROOT / "_downloads"
            csv_files = list(downloads_dir.glob("*.csv")) if downloads_dir.exists() else []
            if not csv_files:
                return []
            csv_path = csv_files[0]
        else:
            csv_path = Path(csv_path)

        if not csv_path.exists():
            return []

        samples = []
        try:
            with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if sample_limit and i >= sample_limit:
                        break

                    # Extract fields: sender, receiver, date, subject, body, label(optional)
                    sender = row.get("sender", "unknown@example.com")
                    receiver = row.get("receiver", "recipient@example.com")
                    subject = row.get("subject", "Test Email")
                    body = row.get("body", "Test body")
                    label = row.get("label")

                    # Construct pseudo-.eml content
                    content = (
                        f"From: {sender}\n"
                        f"To: {receiver}\n"
                        f"Subject: {subject}\n"
                        f"Date: {row.get('date', '')}\n"
                        f"\n{body}\n"
                    )

                    samples.append(
                        DatasetSample(
                            path=f"csv-generated-{csv_path.stem}-{i}",
                            category="fraud",
                            metadata={
                                "source": csv_path.stem,
                                "sender": sender,
                                "label": label,
                            },
                            ground_truth={"label": label} if label else None,
                            content=content,
                        )
                    )
        except Exception as e:
            # Skip CSV files that fail to parse
            pass

        return samples

    @staticmethod
    def load_corpus(sample_limit: Optional[int] = None) -> list[DatasetSample]:
        """Load auto-labeled corpus from corpus.json.

        Args:
            sample_limit: Max samples to load (None = all)

        Returns:
            List of DatasetSample objects with category='corpus'
        """
        corpus_file = DatasetLoader.MAILS_ROOT / "corpus.json"
        samples = []

        if not corpus_file.exists():
            return []

        try:
            with open(corpus_file, "r", encoding="utf-8") as f:
                corpus_data = json.load(f)

            emails = corpus_data.get("emails", [])[:sample_limit]

            for email_entry in emails:
                eml_path = DatasetLoader.MAILS_ROOT / email_entry.get("file", "")
                if not eml_path.exists():
                    continue

                try:
                    content = eml_path.read_text(encoding="utf-8", errors="ignore")
                    ground_truth = email_entry.get("ground_truth", {})

                    samples.append(
                        DatasetSample(
                            path=str(eml_path),
                            category="corpus",
                            metadata={
                                "id": email_entry.get("id"),
                                "source": "auto-labeled corpus",
                                **email_entry.get("metadata", {}),
                            },
                            ground_truth={
                                "country": ground_truth.get("country"),
                                "country_name": ground_truth.get("country_name"),
                                "region": ground_truth.get("region"),
                                "confidence": ground_truth.get("confidence"),
                                "ip": email_entry.get("metadata", {}).get("origin_ip"),
                            },
                            content=content,
                        )
                    )
                except IOError:
                    pass

        except json.JSONDecodeError:
            pass

        return samples

    @staticmethod
    def load_actor_based(sample_limit: Optional[int] = None) -> list[DatasetSample]:
        """Load actor-based labeled samples from ground_truth.json.

        Args:
            sample_limit: Max samples to load (None = all)

        Returns:
            List of DatasetSample objects with category='actor'
        """
        actor_dir = DatasetLoader.MAILS_ROOT / "test1.1.3-Huntertrace"
        ground_truth_file = actor_dir / "ground_truth.json"
        samples = []

        if not ground_truth_file.exists():
            return []

        try:
            with open(ground_truth_file, "r", encoding="utf-8") as f:
                actor_data = json.load(f)

            count = 0
            for actor_id, actor_info in actor_data.items():
                if sample_limit and count >= sample_limit:
                    break

                emails = actor_info.get("emails", [])
                for email_file in emails:
                    if sample_limit and count >= sample_limit:
                        break

                    eml_path = actor_dir / email_file
                    if not eml_path.exists():
                        continue

                    try:
                        content = eml_path.read_text(encoding="utf-8", errors="ignore")
                        samples.append(
                            DatasetSample(
                                path=str(eml_path),
                                category="actor",
                                metadata={
                                    "actor_id": actor_id,
                                    "source": "actor-based ground truth",
                                },
                                ground_truth={
                                    "country": actor_info.get("country"),
                                    "actor": actor_id,
                                    "timezone": actor_info.get("tz_offset"),
                                    "charset": actor_info.get("charset"),
                                    "vpn": actor_info.get("vpn", False),
                                    "difficulty": actor_info.get("difficulty"),
                                },
                                content=content,
                            )
                        )
                        count += 1
                    except IOError:
                        pass

        except json.JSONDecodeError:
            pass

        return samples

    @staticmethod
    def load_email_collection(
        directory: str, sample_limit: Optional[int] = None
    ) -> list[DatasetSample]:
        """Load generic .eml directory.

        Args:
            directory: Directory name (relative to mails/)
            sample_limit: Max samples to load (None = all)

        Returns:
            List of DatasetSample objects
        """
        dir_path = DatasetLoader.MAILS_ROOT / directory
        samples = []

        if not dir_path.exists():
            return []

        eml_files = sorted(dir_path.glob("*.eml"))[:sample_limit]

        for eml_file in eml_files:
            try:
                content = eml_file.read_text(encoding="utf-8", errors="ignore")
                samples.append(
                    DatasetSample(
                        path=str(eml_file),
                        category=directory,
                        metadata={"source": directory, "file": eml_file.name},
                        content=content,
                    )
                )
            except IOError:
                pass

        return samples

    @staticmethod
    def load_all(sample_limit: Optional[int] = None) -> list[DatasetSample]:
        """Load all available datasets.

        Args:
            sample_limit: Max total samples (None = all)

        Returns:
            List of all DatasetSample objects from all sources
        """
        all_samples = []

        # Calculate per-dataset limit to respect total limit
        num_datasets = 5
        per_dataset_limit = (sample_limit // num_datasets) if sample_limit else None

        all_samples.extend(DatasetLoader.load_ceas(per_dataset_limit))
        all_samples.extend(DatasetLoader.load_corpus(per_dataset_limit))
        all_samples.extend(DatasetLoader.load_actor_based(per_dataset_limit))
        all_samples.extend(DatasetLoader.load_fraud_csv(sample_limit=per_dataset_limit))

        # Load other email collections
        for collection_dir in ["emails", "eml_raw", "testMail", "50email"]:
            all_samples.extend(DatasetLoader.load_email_collection(collection_dir, per_dataset_limit))

        # Trim to total limit
        if sample_limit:
            all_samples = all_samples[:sample_limit]

        return all_samples

    @staticmethod
    def create_index() -> dict:
        """Create master index of all available datasets.

        Returns:
            Dictionary with dataset metadata and paths
        """
        index = {
            "mails_root": str(DatasetLoader.MAILS_ROOT),
            "datasets": {
                "ceas": {
                    "path": str(DatasetLoader.MAILS_ROOT / "ceas08_eml"),
                    "format": "eml",
                    "estimated_count": 39154,
                    "has_ground_truth": False,
                },
                "corpus": {
                    "path": str(DatasetLoader.MAILS_ROOT / "corpus.json"),
                    "format": "json",
                    "estimated_count": 200,
                    "has_ground_truth": True,
                },
                "actor": {
                    "path": str(DatasetLoader.MAILS_ROOT / "test1.1.3-Huntertrace"),
                    "format": "eml+json",
                    "estimated_count": 50,
                    "has_ground_truth": True,
                },
                "fraud": {
                    "path": str(DatasetLoader.MAILS_ROOT / "_downloads"),
                    "format": "csv",
                    "estimated_count": 274823,
                    "has_ground_truth": True,
                },
                "emails": {
                    "path": str(DatasetLoader.MAILS_ROOT / "emails"),
                    "format": "eml",
                    "estimated_count": 247,
                    "has_ground_truth": False,
                },
            },
        }
        return index
