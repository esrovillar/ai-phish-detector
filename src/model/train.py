"""
Training Pipeline — Train a Random Forest classifier on extracted features.

Loads features.csv, splits data, trains the model, evaluates performance,
and saves the trained model and metrics.
"""

import json
import os
import pickle

import click
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import train_test_split


FEATURES_CSV = os.path.join("data", "processed", "features.csv")
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phish_detector.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")


@click.command()
@click.option("--input", "-i", "input_file", default=FEATURES_CSV, help="Path to features CSV")
@click.option("--output", "-o", default=MODEL_PATH, help="Path to save trained model")
@click.option("--test-size", default=0.2, help="Test set proportion")
@click.option("--n-estimators", default=200, help="Number of trees in Random Forest")
@click.option("--max-depth", default=20, help="Max tree depth (0 = unlimited)")
@click.option("--random-state", default=42, help="Random seed")
def train(input_file, output, test_size, n_estimators, max_depth, random_state):
    """Train phishing detection model on extracted features."""
    click.echo("🧠 Training Phishing Detection Model")
    click.echo("=" * 50)

    # Load data
    if not os.path.exists(input_file):
        click.echo(f"✗ Features file not found: {input_file}")
        click.echo("  Run preprocessing first: python -m src.data.preprocess")
        return

    df = pd.read_csv(input_file)
    click.echo(f"📊 Loaded {len(df)} samples with {len(df.columns) - 1} features")

    # Separate features and labels
    if "label" not in df.columns:
        click.echo("✗ No 'label' column found in features CSV")
        return

    y = df["label"].astype(int)
    X = df.drop(columns=["label"])

    # Remove any non-numeric columns
    X = X.select_dtypes(include=[np.number])

    # Fill any remaining NaN
    X = X.fillna(0.0)

    click.echo(f"  Phishing: {y.sum()} | Legitimate: {len(y) - y.sum()}")
    click.echo(f"  Features used: {X.shape[1]}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        stratify=y,
        random_state=random_state
    )
    click.echo(f"\n📋 Split: {len(X_train)} train / {len(X_test)} test")

    # Train Random Forest
    click.echo("\n🌲 Training Random Forest classifier...")
    max_d = max_depth if max_depth > 0 else None
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_d,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # Predictions
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    try:
        auc_roc = roc_auc_score(y_test, y_proba)
    except ValueError:
        auc_roc = 0.0

    cm = confusion_matrix(y_test, y_pred)

    click.echo("\n📈 Model Performance:")
    click.echo(f"  Accuracy:  {accuracy:.4f}")
    click.echo(f"  Precision: {precision:.4f}")
    click.echo(f"  Recall:    {recall:.4f}")
    click.echo(f"  F1-Score:  {f1:.4f}")
    click.echo(f"  AUC-ROC:   {auc_roc:.4f}")

    click.echo(f"\n  Confusion Matrix:")
    click.echo(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    click.echo(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    # Feature importance (top 15)
    importances = clf.feature_importances_
    feature_names = X.columns.tolist()
    importance_pairs = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True
    )

    click.echo("\n🔑 Top 15 Important Features:")
    for name, imp in importance_pairs[:15]:
        bar = "█" * int(imp * 50)
        click.echo(f"  {name:40s} {imp:.4f} {bar}")

    # Save model
    os.makedirs(os.path.dirname(output), exist_ok=True)
    model_data = {
        "model": clf,
        "feature_names": feature_names,
        "version": "1.0.0",
    }
    with open(output, "wb") as f:
        pickle.dump(model_data, f)
    click.echo(f"\n💾 Model saved to: {output}")

    # Save metrics
    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "auc_roc": round(auc_roc, 4),
        "confusion_matrix": {
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1]),
        },
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "n_features": X.shape[1],
        "top_features": [
            {"name": name, "importance": round(float(imp), 4)}
            for name, imp in importance_pairs[:20]
        ],
    }

    metrics_path = os.path.join(os.path.dirname(output), "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    click.echo(f"📊 Metrics saved to: {metrics_path}")

    click.echo("\n✅ Training complete!")


if __name__ == "__main__":
    train()
