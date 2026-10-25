# backend/preprocess.py
import os, sys, warnings
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config import (
    NF_UQ_PATH, NF_CIC_PATH, SHARED_FEATURES,
    ATTACK_LABEL_MAP, ATTACK_CLASSES,
    LABEL_COL, ATTACK_COL, SCALER_PATH, ENCODER_PATH
)


def load_nf_uq(sample_size=500_000):
    print("\n[PREPROCESS] Loading NF-UQ-NIDS-v2 (n={:,})...".format(sample_size))
    df = pd.read_csv(
        NF_UQ_PATH,
        usecols=SHARED_FEATURES + [LABEL_COL, ATTACK_COL],
        nrows=sample_size,
        low_memory=False
    )
    df["source"] = "NF_UQ"
    print("  Loaded {:,} rows".format(df.shape[0]))
    print(df[ATTACK_COL].value_counts().head(8).to_string())
    return df


def load_nf_cic(sample_size=300_000):
    print("\n[PREPROCESS] Loading NF-CICIDS2018-v3 (n={:,})...".format(sample_size))
    df = pd.read_csv(
        NF_CIC_PATH,
        usecols=SHARED_FEATURES + [LABEL_COL, ATTACK_COL],
        nrows=sample_size,
        low_memory=False
    )
    df["source"] = "NF_CIC"
    print("  Loaded {:,} rows".format(df.shape[0]))
    print(df[ATTACK_COL].value_counts().head(8).to_string())
    return df


def normalise_labels(df):
    print("\n[PREPROCESS] Normalising labels...")
    df["attack_label"] = df[ATTACK_COL].map(ATTACK_LABEL_MAP).fillna("OTHER")
    df["binary_label"] = (df["attack_label"] != "BENIGN").astype(int)
    print(df["attack_label"].value_counts().to_string())
    return df


def clean_data(df):
    before = len(df)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    f32_max = float(np.finfo(np.float32).max) * 0.99
    for col in SHARED_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
            df[col] = df[col].clip(-f32_max, f32_max)
    df.drop_duplicates(subset=SHARED_FEATURES, inplace=True)
    print("\n[PREPROCESS] Cleaned: {:,} -> {:,} rows".format(before, len(df)))
    return df


def balance_classes(df, max_per=80_000):
    print("\n[PREPROCESS] Balancing classes (max={:,}/class)...".format(max_per))
    frames = []
    for label, group in df.groupby("attack_label"):
        n = min(len(group), max_per)
        frames.append(group.sample(n, random_state=42))
    bal = pd.concat(frames, ignore_index=True)

    # FIX 1: shuffle the entire balanced dataframe with a fixed seed
    # This ensures classes are interleaved before the train/test split
    # so both splits see the same class distribution in the same order
    bal = bal.sample(frac=1, random_state=42).reset_index(drop=True)

    print(bal["attack_label"].value_counts().to_string())
    return bal


def scale_and_encode(X_train, X_test, y_train, y_test):
    print("\n[PREPROCESS] Scaling and encoding...")
    scaler = StandardScaler()
    Xtr    = scaler.fit_transform(X_train)
    Xte    = scaler.transform(X_test)
    le     = LabelEncoder()
    le.fit(ATTACK_CLASSES)
    ytr = le.transform(y_train)
    yte = le.transform(y_test)
    os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)
    print("  Scaler  -> " + SCALER_PATH)
    print("  Encoder -> " + ENCODER_PATH)
    print("  Classes: {}".format(le.classes_.tolist()))
    return Xtr, Xte, ytr, yte, le


def run_preprocessing(uq_sample=500_000, cic_sample=300_000,
                      max_per=80_000, test_size=0.2):
    print("=" * 55)
    print("  Dataset Preprocessing Pipeline")
    print("=" * 55)

    # 1. Load both datasets
    df = pd.concat(
        [load_nf_uq(uq_sample), load_nf_cic(cic_sample)],
        ignore_index=True
    )
    print("\n[PREPROCESS] Combined: {:,} rows".format(df.shape[0]))

    # 2. Normalise labels
    df = normalise_labels(df)

    # 3. Clean and clip
    df = clean_data(df)

    # 4. Balance classes (includes internal shuffle)
    df = balance_classes(df, max_per)

    # 5. Build feature matrix
    X       = df[SHARED_FEATURES].values.astype(np.float32)
    y_bin   = df["binary_label"].values
    y_multi = df["attack_label"].values
    print("\n[PREPROCESS] Feature matrix: {}".format(X.shape))

    # 6. Safety check
    if not np.isfinite(X).all():
        print("[PREPROCESS] WARNING: non-finite values — clipping")
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)

    # 7. Train/test split
    # FIX 2: stratify on y_multi (multi-class) not y_bin (binary)
    # This guarantees every attack class appears in both train and test
    # in the correct proportion — not just the benign/attack ratio
    (X_train, X_test,
     yb_train, yb_test,
     ym_train, ym_test) = train_test_split(
        X, y_bin, y_multi,
        test_size    = test_size,
        random_state = 42,
        shuffle      = True,       # explicit — ensures random ordering
        stratify     = y_multi,    # FIX: stratify by attack class not binary
    )
    print("  Train: {:,}  Test: {:,}".format(
        X_train.shape[0], X_test.shape[0]))

    # Verify class distribution in test set
    unique, counts = np.unique(ym_test, return_counts=True)
    print("  Test class distribution:")
    for cls, cnt in zip(unique, counts):
        print("    {:20s} {:,}".format(cls, cnt))

    # 8. Scale features + encode labels
    Xtr, Xte, ytr, yte, le = scale_and_encode(
        X_train, X_test, ym_train, ym_test
    )

    print("\n[PREPROCESS] Complete")
    return Xtr, Xte, yb_train, yb_test, ytr, yte, le


if __name__ == "__main__":
    run_preprocessing()