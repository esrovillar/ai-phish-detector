"""
Preprocessor — Load .eml files, extract features, create labeled dataset.

Walks data/emails/phishing/ and data/emails/legitimate/ directories,
extracts features using the feature engine, and saves as features.csv.
"""

import email
import os

import click
import pandas as pd

from src.features.feature_engine import extract_features_from_file


DATA_DIR = os.path.join("data", "emails")
OUTPUT_DIR = os.path.join("data", "processed")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "features.csv")


def _load_emails_from_dir(directory: str, label: int) -> list:
    """
    Load all .eml files from a directory and extract features.

    Args:
        directory: Path to directory containing .eml files.
        label: 1 for phishing, 0 for legitimate.

    Returns:
        List of feature dicts with 'label' key added.
    """
    records = []
    if not os.path.isdir(directory):
        click.echo(f"  ⚠️  Directory not found: {directory}")
        return records

    files = [f for f in os.listdir(directory) if f.endswith(".eml")]
    click.echo(f"  Processing {len(files)} files from {directory}...")

    for i, filename in enumerate(sorted(files)):
        filepath = os.path.join(directory, filename)
        try:
            features = extract_features_from_file(filepath)
            features["label"] = float(label)
            features["source_file"] = filename
            records.append(features)
        except Exception as e:
            click.echo(f"    ✗ Error processing {filename}: {e}")

        # Progress indicator
        if (i + 1) % 50 == 0:
            click.echo(f"    ... processed {i + 1}/{len(files)}")

    return records


@click.command()
@click.option("--data-dir", "-d", default=DATA_DIR, help="Directory with phishing/ and legitimate/ subdirs")
@click.option("--output", "-o", default=OUTPUT_FILE, help="Output CSV path")
def preprocess(data_dir, output):
    """Load .eml files, extract features, and save as labeled CSV."""
    phishing_dir = os.path.join(data_dir, "phishing")
    legitimate_dir = os.path.join(data_dir, "legitimate")

    click.echo("🔄 Preprocessing email dataset...")

    # Extract features from both classes
    phishing_records = _load_emails_from_dir(phishing_dir, label=1)
    legitimate_records = _load_emails_from_dir(legitimate_dir, label=0)

    all_records = phishing_records + legitimate_records

    if not all_records:
        click.echo("✗ No emails found. Run download_datasets first.")
        return

    # Create DataFrame
    df = pd.DataFrame(all_records)

    # Drop non-numeric columns (except label) for the feature CSV
    source_files = df.pop("source_file") if "source_file" in df.columns else None

    # Fill NaN with 0 (missing features from failed extraction)
    df = df.fillna(0.0)

    # Save
    os.makedirs(os.path.dirname(output), exist_ok=True)
    df.to_csv(output, index=False)

    click.echo(f"\n📊 Dataset Summary:")
    click.echo(f"  Total samples:  {len(df)}")
    click.echo(f"  Phishing:       {int(df['label'].sum())}")
    click.echo(f"  Legitimate:     {int(len(df) - df['label'].sum())}")
    click.echo(f"  Features:       {len(df.columns) - 1}")
    click.echo(f"  Saved to:       {output}")
    click.echo("✅ Preprocessing complete!")


if __name__ == "__main__":
    preprocess()
