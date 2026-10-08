"""Train phishing classifiers for emails and/or URLs.

Usage:
    python train.py --email data/Phishing_Email.csv --url data/malicious_phish.csv
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

os.makedirs("models", exist_ok=True)


def load_email(path):
    # Kaggle "Phishing Email Detection" dataset: columns "Email Text", "Email Type"
    df = pd.read_csv(path).dropna(subset=["Email Text"]).drop_duplicates("Email Text")
    X = df["Email Text"].astype(str)
    y = (df["Email Type"] == "Phishing Email").astype(int)
    return X, y


def load_url(path):
    # Kaggle "Malicious URLs" dataset: columns "url", "type"
    df = pd.read_csv(path).dropna(subset=["url"]).drop_duplicates("url")
    df = df[df["type"].isin(["benign", "phishing"])]
    X = df["url"].astype(str)
    y = (df["type"] == "phishing").astype(int)
    return X, y


def email_pipeline():
    return make_pipeline(
        TfidfVectorizer(stop_words="english", ngram_range=(1, 2),
                        max_features=50000, sublinear_tf=True),
        LogisticRegression(max_iter=1000, class_weight="balanced"),
    )


def url_pipeline():
    # Character n-grams catch tricks like "paypa1", "-secure-login", odd TLDs
    return make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                        max_features=100000, sublinear_tf=True),
        LogisticRegression(max_iter=1000, class_weight="balanced"),
    )


def train(name, X, y, pipe):
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    pipe.fit(X_tr, y_tr)
    proba = pipe.predict_proba(X_te)[:, 1]
    print(f"\n=== {name} model ===")
    print(classification_report(y_te, (proba >= 0.5).astype(int),
                                target_names=["legit", "phishing"], digits=3))
    print(f"ROC-AUC: {roc_auc_score(y_te, proba):.3f}")
    joblib.dump(pipe, f"models/{name}_model.joblib")
    print(f"Saved models/{name}_model.joblib")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", help="path to email CSV")
    ap.add_argument("--url", help="path to URL CSV")
    args = ap.parse_args()
    if not (args.email or args.url):
        ap.error("pass --email and/or --url")
    if args.email:
        train("email", *load_email(args.email), email_pipeline())
    if args.url:
        train("url", *load_url(args.url), url_pipeline())
