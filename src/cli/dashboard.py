"""
CLI Dashboard — Rich terminal dashboard for AI-Phish-Detector.

Shows model metrics, analysis history, and system status.
"""

import json
import os
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich import box


console = Console()

MODEL_PATH = os.path.join("models", "phish_detector.pkl")
METRICS_PATH = os.path.join("models", "metrics.json")
FEATURES_CSV = os.path.join("data", "processed", "features.csv")
SAMPLES_DIR = os.path.join("data", "samples")


def _load_metrics() -> dict:
    """Load model metrics from JSON file."""
    if not os.path.exists(METRICS_PATH):
        return {}
    with open(METRICS_PATH, "r") as f:
        return json.load(f)


def _model_status_panel() -> Panel:
    """Create model status panel."""
    content = Text()

    if os.path.exists(MODEL_PATH):
        mtime = datetime.fromtimestamp(os.path.getmtime(MODEL_PATH))
        size_kb = os.path.getsize(MODEL_PATH) / 1024
        content.append("Status: ", style="dim")
        content.append("TRAINED ✅\n", style="bold green")
        content.append(f"File:   {MODEL_PATH}\n", style="dim")
        content.append(f"Size:   {size_kb:.1f} KB\n", style="dim")
        content.append(f"Date:   {mtime.strftime('%Y-%m-%d %H:%M')}\n", style="dim")
    else:
        content.append("Status: ", style="dim")
        content.append("NOT TRAINED ❌\n", style="bold red")
        content.append("Run: python -m src.model.train\n", style="yellow")

    return Panel(content, title="🧠 Model", border_style="blue", box=box.ROUNDED)


def _metrics_panel(metrics: dict) -> Panel:
    """Create metrics display panel."""
    if not metrics:
        content = Text("No metrics available.\nTrain a model first.", style="dim")
        return Panel(content, title="📈 Metrics", border_style="yellow", box=box.ROUNDED)

    content = Text()

    # Performance metrics with color coding
    perf_items = [
        ("Accuracy", metrics.get("accuracy", 0), 0.9),
        ("Precision", metrics.get("precision", 0), 0.85),
        ("Recall", metrics.get("recall", 0), 0.85),
        ("F1-Score", metrics.get("f1_score", 0), 0.85),
        ("AUC-ROC", metrics.get("auc_roc", 0), 0.9),
    ]

    for name, value, threshold in perf_items:
        color = "green" if value >= threshold else "yellow" if value >= 0.7 else "red"
        bar_len = int(value * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        content.append(f"  {name:12s} ", style="white")
        content.append(f"{value:.4f} ", style=f"bold {color}")
        content.append(f"{bar}\n", style=color)

    # Confusion matrix
    cm = metrics.get("confusion_matrix", {})
    if cm:
        content.append("\n  Confusion Matrix:\n", style="bold")
        content.append(f"    TN={cm.get('true_negatives', 0):4d}  ", style="green")
        content.append(f"FP={cm.get('false_positives', 0):4d}\n", style="red")
        content.append(f"    FN={cm.get('false_negatives', 0):4d}  ", style="red")
        content.append(f"TP={cm.get('true_positives', 0):4d}\n", style="green")

    # Dataset info
    content.append(f"\n  Train: {metrics.get('train_samples', '?')} samples", style="dim")
    content.append(f"  |  Test: {metrics.get('test_samples', '?')} samples\n", style="dim")
    content.append(f"  Features: {metrics.get('n_features', '?')}\n", style="dim")

    return Panel(content, title="📈 Performance Metrics", border_style="green", box=box.ROUNDED)


def _top_features_panel(metrics: dict) -> Panel:
    """Create top features panel."""
    top_features = metrics.get("top_features", [])

    if not top_features:
        content = Text("No feature data available.", style="dim")
        return Panel(content, title="🔑 Top Features", border_style="cyan", box=box.ROUNDED)

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Feature", min_width=30)
    table.add_column("Importance", justify="right", width=12)
    table.add_column("", width=15)

    max_imp = top_features[0]["importance"] if top_features else 1

    for i, feat in enumerate(top_features[:15], 1):
        bar_len = int((feat["importance"] / max(max_imp, 0.001)) * 12)
        bar = "█" * bar_len
        color = "red" if i <= 3 else "yellow" if i <= 7 else "green"
        table.add_row(
            str(i),
            feat["name"],
            f"{feat['importance']:.4f}",
            Text(bar, style=color),
        )

    return Panel(table, title="🔑 Top Features", border_style="cyan", box=box.ROUNDED)


def _data_status_panel() -> Panel:
    """Create data status panel."""
    content = Text()

    # Check for training data
    emails_dir = os.path.join("data", "emails")
    phishing_count = 0
    legit_count = 0

    phishing_dir = os.path.join(emails_dir, "phishing")
    legit_dir = os.path.join(emails_dir, "legitimate")

    if os.path.isdir(phishing_dir):
        phishing_count = len([f for f in os.listdir(phishing_dir) if f.endswith(".eml")])
    if os.path.isdir(legit_dir):
        legit_count = len([f for f in os.listdir(legit_dir) if f.endswith(".eml")])

    content.append("Training Data:\n", style="bold")
    content.append(f"  Phishing:    {phishing_count:5d} emails\n",
                   style="green" if phishing_count > 0 else "red")
    content.append(f"  Legitimate:  {legit_count:5d} emails\n",
                   style="green" if legit_count > 0 else "red")

    # Features CSV
    if os.path.exists(FEATURES_CSV):
        size_kb = os.path.getsize(FEATURES_CSV) / 1024
        content.append(f"\n  Features CSV: ✅ ({size_kb:.1f} KB)\n", style="green")
    else:
        content.append(f"\n  Features CSV: ❌ Not generated\n", style="red")

    # Sample emails
    if os.path.isdir(SAMPLES_DIR):
        sample_count = len([f for f in os.listdir(SAMPLES_DIR) if f.endswith(".eml")])
        content.append(f"  Samples:     {sample_count} files\n", style="dim")

    return Panel(content, title="📦 Data", border_style="yellow", box=box.ROUNDED)


def _quickstart_panel() -> Panel:
    """Quick start guide panel."""
    content = Text()
    content.append("Quick Commands:\n\n", style="bold")

    commands = [
        ("Download data", "python -m src.data.download_datasets"),
        ("Preprocess", "python -m src.data.preprocess"),
        ("Train model", "python -m src.model.train"),
        ("Analyze file", "python -m src.cli.analyze --file email.eml"),
        ("Batch scan", "python -m src.cli.analyze --dir ./emails/"),
    ]

    for desc, cmd in commands:
        content.append(f"  {desc:16s} ", style="cyan")
        content.append(f"{cmd}\n", style="dim")

    return Panel(content, title="🚀 Quick Start", border_style="magenta", box=box.ROUNDED)


@click.command()
def dashboard():
    """Display AI-Phish-Detector dashboard."""
    console.clear()
    console.print(
        Panel(
            Text("AI-Phish-Detector", style="bold white", justify="center"),
            subtitle="Machine Learning Phishing Detection",
            border_style="bright_blue",
            box=box.DOUBLE,
        )
    )
    console.print()

    metrics = _load_metrics()

    # Top row: Model status + Data status
    console.print(Columns([
        _model_status_panel(),
        _data_status_panel(),
    ], equal=True, expand=True))

    # Metrics panel
    console.print(_metrics_panel(metrics))

    # Top features
    if metrics:
        console.print(_top_features_panel(metrics))

    # Quick start
    console.print(_quickstart_panel())

    console.print(
        f"[dim]Dashboard generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
    )


if __name__ == "__main__":
    dashboard()
