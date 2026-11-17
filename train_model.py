from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"

MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

DATA_CANDIDATES = [
    DATA_DIR / "job_postings_train.csv",
    DATA_DIR / "fake_job_postings.csv",
]

TEXT_COLUMNS = [
    "title",
    "location",
    "department",
    "salary_range",
    "company_profile",
    "description",
    "requirements",
    "benefits",
    "employment_type",
    "required_experience",
    "required_education",
    "industry",
    "function",
]


def load_dataset():
    for path in DATA_CANDIDATES:
        if path.exists():
            print(f"Loading dataset: {path.name}")
            return pd.read_csv(path)

    raise FileNotFoundError(
        "Dataset not found. Put job_postings_train.csv "
        "or fake_job_postings.csv inside the data folder."
    )


def prepare_data(df):
    if "fraudulent" not in df.columns:
        raise ValueError(
            "The dataset must contain a 'fraudulent' target column."
        )

    available_columns = [
        column for column in TEXT_COLUMNS if column in df.columns
    ]

    if not available_columns:
        raise ValueError("No expected text columns were found.")

    df = df.copy()
    df["fraudulent"] = pd.to_numeric(
        df["fraudulent"], errors="coerce"
    )
    df = df.dropna(subset=["fraudulent"])
    df["fraudulent"] = df["fraudulent"].astype(int)

    df = df[df["fraudulent"].isin([0, 1])].copy()

    for column in available_columns:
        df[column] = df[column].fillna("").astype(str)

    df["combined_text"] = df[available_columns].agg(" ".join, axis=1)
    df["combined_text"] = df["combined_text"].str.strip()

    df = df[df["combined_text"].str.len() > 0].copy()

    if df["fraudulent"].nunique() != 2:
        raise ValueError(
            "The dataset must contain both genuine (0) and fraudulent (1) rows."
        )

    return df


def main():
    df = prepare_data(load_dataset())

    print("\nDataset overview")
    print("----------------")
    print(f"Total records: {len(df)}")
    print("\nClass counts:")
    print(df["fraudulent"].value_counts().sort_index())

    X = df["combined_text"]
    y = df["fraudulent"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),
                min_df=2,
                max_features=150000,
                sublinear_tf=True,
                strip_accents="unicode",
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                C=2.0,
                solver="liblinear",
                random_state=42,
            ),
        ),
    ])

    print("\nTraining model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )
    average_precision = average_precision_score(
        y_test, probabilities
    )
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])

    print("\nMODEL EVALUATION")
    print("----------------")
    print(f"Accuracy:          {accuracy:.4f}")
    print(f"Fraud precision:   {precision:.4f}")
    print(f"Fraud recall:      {recall:.4f}")
    print(f"Fraud F1-score:    {f1:.4f}")
    print(f"Average precision: {average_precision:.4f}")

    print("\nConfusion matrix")
    print("Rows = actual, columns = predicted")
    print(matrix)

    print("\nClassification report")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Genuine", "Fraudulent"],
        zero_division=0,
    ))

    model_path = MODEL_DIR / "scamshield_model.pkl"
    joblib.dump(model, model_path)

    report = {
        "dataset_rows": int(len(df)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "genuine_rows": int((y == 0).sum()),
        "fraudulent_rows": int((y == 1).sum()),
        "accuracy": float(accuracy),
        "fraud_precision": float(precision),
        "fraud_recall": float(recall),
        "fraud_f1_score": float(f1),
        "average_precision": float(average_precision),
        "confusion_matrix": matrix.tolist(),
    }

    report_path = REPORT_DIR / "evaluation.json"
    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nModel saved to: {model_path}")
    print(f"Evaluation saved to: {report_path}")
    print("\nTraining completed.")


if __name__ == "__main__":
    main()