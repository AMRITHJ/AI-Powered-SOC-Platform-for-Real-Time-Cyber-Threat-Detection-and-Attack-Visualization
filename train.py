# backend/train.py
# ─────────────────────────────────────────────────────────────
#  ML Model Training
#  Run: python -m backend.train
#  Outputs:
#    backend/models/attack_model.pkl    ← Random Forest
#    backend/models/iso_forest.pkl      ← Isolation Forest
#    backend/models/scaler.pkl          ← StandardScaler
#    backend/models/label_encoder.pkl   ← LabelEncoder
#    backend/models/rf_evaluation.json  ← accuracy/F1 results
#    backend/models/iso_evaluation.json
# ─────────────────────────────────────────────────────────────
import os, sys, time, json, joblib, numpy as np, warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics  import (
    accuracy_score, precision_score,
    recall_score, f1_score, classification_report
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config     import (MODEL_PATH, ISO_MODEL_PATH,
                                 ATTACK_CLASSES, SHARED_FEATURES)
from backend.preprocess import run_preprocessing


# ── Random Forest ─────────────────────────────────────────────
def train_rf(X_train, y_train_enc, le):
    print(f"\n[TRAIN] Training Random Forest...")
    print(f"  Samples  : {X_train.shape[0]:,}")
    print(f"  Features : {X_train.shape[1]}")
    print(f"  Classes  : {le.classes_.tolist()}")

    rf = RandomForestClassifier(
        n_estimators     = 200,
        max_depth        = 20,
        min_samples_leaf = 5,
        class_weight     = "balanced",
        n_jobs           = -1,
        random_state     = 42,
        verbose          = 1,
    )
    t0 = time.time()
    rf.fit(X_train, y_train_enc)
    print(f"  Time: {time.time() - t0:.1f}s")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(rf, MODEL_PATH)
    print(f"  Saved → {MODEL_PATH}")
    return rf


def eval_rf(rf, X_test, y_test_enc, le):
    print("\n[TRAIN] Evaluating Random Forest...")
    y_pred = rf.predict(X_test)

    acc  = accuracy_score(y_test_enc, y_pred)
    prec = precision_score(y_test_enc, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_test_enc, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_test_enc, y_pred, average="weighted", zero_division=0)

    print(f"\n  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1 Score  : {f1*100:.2f}%")

    # ── Per-class report ──────────────────────────────────────
    # Only include class indices that actually appear in test/pred
    # (avoids mismatch when some classes have 0 samples)
    print("\n  Per-class report:")
    present_labels = sorted(set(y_test_enc.tolist()) | set(y_pred.tolist()))
    present_names  = [le.classes_[i] for i in present_labels]
    print(classification_report(
        y_test_enc, y_pred,
        labels       = present_labels,
        target_names = present_names,
        zero_division = 0
    ))

    # ── Feature importance ────────────────────────────────────
    imp   = rf.feature_importances_
    top10 = np.argsort(imp)[::-1][:10]
    print("  Top 10 most important features:")
    for rank, idx in enumerate(top10, 1):
        print(f"    {rank:2}. {SHARED_FEATURES[idx]:<38} {imp[idx]:.4f}")

    result = {
        "accuracy":     round(acc,  4),
        "precision":    round(prec, 4),
        "recall":       round(rec,  4),
        "f1_score":     round(f1,   4),
        "n_test":       int(len(y_test_enc)),
        "classes":      le.classes_.tolist(),
        "present_classes": present_names,
        "top_features": [
            {
                "feature":    SHARED_FEATURES[i],
                "importance": round(float(imp[i]), 4)
            }
            for i in top10
        ],
    }

    path = "backend/models/rf_evaluation.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(result, open(path, "w"), indent=2)
    print(f"\n  Evaluation saved → {path}")
    return result


# ── Isolation Forest ──────────────────────────────────────────
def train_iso(X_train):
    print("\n[TRAIN] Training Isolation Forest...")
    iso = IsolationForest(
        n_estimators  = 100,
        contamination = 0.15,
        n_jobs        = -1,
        random_state  = 42,
        verbose       = 1,
    )
    t0 = time.time()
    iso.fit(X_train)
    print(f"  Time: {time.time() - t0:.1f}s")
    joblib.dump(iso, ISO_MODEL_PATH)
    print(f"  Saved → {ISO_MODEL_PATH}")
    return iso


def eval_iso(iso, X_test, y_bin_test):
    print("\n[TRAIN] Evaluating Isolation Forest...")
    raw  = iso.predict(X_test)
    pred = np.where(raw == -1, 1, 0)

    acc  = accuracy_score(y_bin_test, pred)
    prec = precision_score(y_bin_test, pred, zero_division=0)
    rec  = recall_score(y_bin_test, pred, zero_division=0)
    f1   = f1_score(y_bin_test, pred, zero_division=0)

    print(f"  Accuracy  : {acc*100:.2f}%")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1 Score  : {f1*100:.2f}%")
    print(f"  Note: Isolation Forest is unsupervised —")
    print(f"        lower accuracy vs RF is expected")

    result = {
        "accuracy":  round(acc,  4),
        "precision": round(prec, 4),
        "recall":    round(rec,  4),
        "f1_score":  round(f1,   4),
    }
    path = "backend/models/iso_evaluation.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(result, open(path, "w"), indent=2)
    print(f"  Evaluation saved → {path}")
    return result


# ── Skip-preprocess mode ──────────────────────────────────────
def load_existing_models():
    """
    If models already exist, load them and re-run evaluation
    without re-training. Used after a partial run.
    """
    needed = [MODEL_PATH, "backend/models/scaler.pkl",
              "backend/models/label_encoder.pkl"]
    return all(os.path.exists(p) and os.path.getsize(p) > 1000
               for p in needed)


# ── Main ──────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  SOC Platform — ML Model Training")
    print("  Random Forest + Isolation Forest")
    print("  Datasets: NF-UQ-NIDS-v2 + NF-CICIDS2018-v3")
    print("=" * 60)

    # Step 1: Preprocess datasets
    (X_train, X_test,
     yb_train, yb_test,
     ytr, yte, le) = run_preprocessing(
        uq_sample  = 500_000,
        cic_sample = 300_000,
        max_per    = 80_000,
    )

    # Step 2: Train Random Forest
    rf      = train_rf(X_train, ytr, le)
    rf_eval = eval_rf(rf, X_test, yte, le)

    # Step 3: Train Isolation Forest
    iso      = train_iso(X_train)
    iso_eval = eval_iso(iso, X_test, yb_test)

    # Step 4: Summary
    print("\n" + "=" * 60)
    print("  Training Complete — Summary")
    print("=" * 60)
    print(f"  Random Forest")
    print(f"    Accuracy  : {rf_eval['accuracy']  * 100:.2f}%")
    print(f"    Precision : {rf_eval['precision'] * 100:.2f}%")
    print(f"    Recall    : {rf_eval['recall']    * 100:.2f}%")
    print(f"    F1 Score  : {rf_eval['f1_score']  * 100:.2f}%")
    print(f"  Isolation Forest")
    print(f"    Accuracy  : {iso_eval['accuracy'] * 100:.2f}%")
    print(f"\n  Saved model files:")
    print(f"    {MODEL_PATH}")
    print(f"    {ISO_MODEL_PATH}")
    print(f"    backend/models/scaler.pkl")
    print(f"    backend/models/label_encoder.pkl")
    print(f"    backend/models/rf_evaluation.json")
    print(f"    backend/models/iso_evaluation.json")
    print(f"\n  Next step:")
    print(f"    python run.py")
    print("=" * 60)


if __name__ == "__main__":
    main()