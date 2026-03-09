"""
CLI Analyze Tool — Scan .eml files for phishing indicators.

Provides --file and --dir options for single or batch analysis,
with Rich formatted output and color-coded verdicts.
"""

import os
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from src.model.predict import PhishDetector, AnalysisResult


console = Console()


def _verdict_style(verdict: str) -> str:
    """Return Rich style string for verdict."""
    styles = {
        "PHISHING": "bold red",
        "SUSPICIOUS": "bold yellow",
        "LEGITIMATE": "bold green",
        "ERROR": "bold magenta",
    }
    return styles.get(verdict, "white")


def _verdict_emoji(verdict: str) -> str:
    """Return emoji for verdict."""
    emojis = {
        "PHISHING": "🚨",
        "SUSPICIOUS": "⚠️",
        "LEGITIMATE": "✅",
        "ERROR": "❌",
    }
    return emojis.get(verdict, "❓")


def _display_result(result: AnalysisResult, filename: str):
    """Display a single analysis result with Rich formatting."""
    emoji = _verdict_emoji(result.verdict)
    style = _verdict_style(result.verdict)

    # Header panel
    title = Text()
    title.append(f"{emoji} {result.verdict}", style=style)
    title.append(f"  Score: {result.score:.1f}/100")

    panel_content = Text()
    panel_content.append(f"File: {filename}\n", style="dim")
    panel_content.append(f"Mode: {'ML Model' if result.model_loaded else 'Heuristic (no model)'}\n", style="dim")

    if result.error:
        panel_content.append(f"\nError: {result.error}", style="red")

    console.print(Panel(panel_content, title=title, border_style=style, box=box.ROUNDED))

    # Top indicators table
    if result.top_indicators:
        table = Table(
            title="Top Contributing Indicators",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Indicator", style="white", min_width=35)
        table.add_column("Score", justify="right", style="yellow", min_width=8)
        table.add_column("Bar", min_width=20)

        max_val = max(v for _, v in result.top_indicators) if result.top_indicators else 1
        for name, value in result.top_indicators[:10]:
            bar_len = int((value / max(max_val, 0.001)) * 20)
            bar = "█" * bar_len
            bar_style = "red" if value > max_val * 0.7 else "yellow" if value > max_val * 0.3 else "green"
            table.add_row(name, f"{value:.3f}", Text(bar, style=bar_style))

        console.print(table)

    # Key features summary
    features = result.features
    if features:
        summary_items = []
        if features.get("header_spf_fail"):
            summary_items.append(("SPF", "FAIL", "red"))
        elif features.get("header_spf_pass"):
            summary_items.append(("SPF", "PASS", "green"))

        if features.get("header_dkim_fail"):
            summary_items.append(("DKIM", "FAIL", "red"))
        elif features.get("header_dkim_pass"):
            summary_items.append(("DKIM", "PASS", "green"))

        if features.get("header_dmarc_fail"):
            summary_items.append(("DMARC", "FAIL", "red"))
        elif features.get("header_dmarc_pass"):
            summary_items.append(("DMARC", "PASS", "green"))

        if features.get("url_total_count", 0) > 0:
            summary_items.append(("URLs", str(int(features["url_total_count"])), "cyan"))
        if features.get("url_typosquat_count", 0) > 0:
            summary_items.append(("Typosquats", str(int(features["url_typosquat_count"])), "red"))
        if features.get("content_urgency_word_count", 0) > 0:
            summary_items.append(("Urgency Words", str(int(features["content_urgency_word_count"])), "yellow"))

        if summary_items:
            summary = Text("  ")
            for label, value, color in summary_items:
                summary.append(f"[{label}: ", style="dim")
                summary.append(value, style=color)
                summary.append("]  ", style="dim")
            console.print(summary)

    console.print()


def _display_batch_summary(results: list):
    """Display summary table for batch analysis."""
    table = Table(
        title="📊 Batch Analysis Summary",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold",
    )
    table.add_column("File", style="white", max_width=40)
    table.add_column("Score", justify="right")
    table.add_column("Verdict", justify="center")

    phishing = suspicious = legitimate = errors = 0

    for filename, result in sorted(results, key=lambda x: x[1].score, reverse=True):
        style = _verdict_style(result.verdict)
        emoji = _verdict_emoji(result.verdict)
        table.add_row(
            filename,
            f"{result.score:.1f}",
            Text(f"{emoji} {result.verdict}", style=style),
        )
        if result.verdict == "PHISHING":
            phishing += 1
        elif result.verdict == "SUSPICIOUS":
            suspicious += 1
        elif result.verdict == "LEGITIMATE":
            legitimate += 1
        else:
            errors += 1

    console.print(table)

    # Stats
    total = len(results)
    console.print(f"\n  Total: {total}  |  "
                  f"[red]🚨 Phishing: {phishing}[/]  |  "
                  f"[yellow]⚠️  Suspicious: {suspicious}[/]  |  "
                  f"[green]✅ Legitimate: {legitimate}[/]")
    if errors:
        console.print(f"  [magenta]❌ Errors: {errors}[/]")
    console.print()


@click.command()
@click.option("--file", "-f", "file_path", help="Path to a single .eml file to analyze")
@click.option("--dir", "-d", "dir_path", help="Path to directory of .eml files for batch scanning")
@click.option("--model", "-m", default=None, help="Path to trained model (optional)")
@click.option("--verbose", "-v", is_flag=True, help="Show all extracted features")
def analyze(file_path, dir_path, model, verbose):
    """Analyze email(s) for phishing indicators."""
    if not file_path and not dir_path:
        click.echo("Error: Provide --file or --dir option.")
        click.echo("Usage: python -m src.cli.analyze --file email.eml")
        sys.exit(1)

    detector = PhishDetector(model_path=model)

    if not detector.model_loaded:
        console.print("[dim]ℹ️  No trained model found. Using heuristic scoring.[/dim]")
        console.print("[dim]   Train a model: python -m src.model.train[/dim]\n")

    if file_path:
        # Single file analysis
        if not os.path.isfile(file_path):
            console.print(f"[red]✗ File not found: {file_path}[/red]")
            sys.exit(1)

        console.print(f"🔍 Analyzing: {file_path}\n")
        result = detector.analyze_email(file_path)
        _display_result(result, os.path.basename(file_path))

        if verbose and result.features:
            table = Table(title="All Features", box=box.SIMPLE)
            table.add_column("Feature", style="cyan")
            table.add_column("Value", justify="right")
            for name, val in sorted(result.features.items()):
                table.add_row(name, f"{val:.4f}")
            console.print(table)

    elif dir_path:
        # Batch directory analysis
        if not os.path.isdir(dir_path):
            console.print(f"[red]✗ Directory not found: {dir_path}[/red]")
            sys.exit(1)

        eml_files = [f for f in os.listdir(dir_path) if f.endswith(".eml")]
        if not eml_files:
            console.print(f"[yellow]No .eml files found in {dir_path}[/yellow]")
            sys.exit(0)

        console.print(f"🔍 Scanning {len(eml_files)} emails in: {dir_path}\n")

        results = []
        with console.status("[bold green]Analyzing emails..."):
            for filename in sorted(eml_files):
                filepath = os.path.join(dir_path, filename)
                result = detector.analyze_email(filepath)
                results.append((filename, result))

        # Show individual results for high-risk items
        for filename, result in results:
            if result.verdict in ("PHISHING", "SUSPICIOUS"):
                _display_result(result, filename)

        # Show summary
        _display_batch_summary(results)


if __name__ == "__main__":
    analyze()
