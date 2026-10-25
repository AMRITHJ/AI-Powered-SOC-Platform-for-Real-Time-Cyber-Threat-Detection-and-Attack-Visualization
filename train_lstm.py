# backend/train_lstm.py
import os
import sys
import json
import warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.preprocess import run_preprocessing
from backend.ai.lstm_classifier import (
    train_lstm,
    evaluate_lstm,
    SEQ_LEN,
    LSTM_MODEL_PATH,
    LSTM_META_PATH,
)


def main():
    print("=" * 55)
    print("  SOC Platform -- LSTM Model Training")
    print("  Bidirectional 2-layer LSTM (PyTorch)")
    print("  Seq len: {} flows per sample".format(SEQ_LEN))
    print("=" * 55)

    # Step 1 -- preprocess (same pipeline as RF)
    result = run_preprocessing(
        uq_sample  = 500000,
        cic_sample = 300000,
        max_per    = 80000,
    )
    X_train = result[0]
    X_test  = result[1]
    ytr     = result[4]
    yte     = result[5]
    le      = result[6]

    # Step 2 -- train LSTM
    # Data is shuffled inside train_lstm before sequencing
    meta = train_lstm(X_train, ytr, X_test, yte, le)

    # Step 3 -- evaluate correctly
    # evaluate_lstm shuffles test data before building sequences
    # and uses majority-vote labels to avoid class-ordering bias
    eval_result = evaluate_lstm(X_test, yte, le)

    # Step 4 -- summary
    bva = meta.get("best_val_acc", 0)
    ta  = eval_result.get("accuracy",  0)
    tf1 = eval_result.get("f1_score",  0)

    print("\n" + "=" * 55)
    print("  LSTM Training Complete -- Summary")
    print("=" * 55)
    print("  Best val accuracy : {:.2f}%".format(bva * 100))
    print("  Test accuracy     : {:.2f}%".format(ta  * 100))
    print("  Test F1 score     : {:.2f}%".format(tf1 * 100))

    # Compare with Random Forest
    try:
        rf_path = "backend/models/rf_evaluation.json"
        with open(rf_path) as fh:
            rf = json.load(fh)
        rf_acc = rf.get("accuracy", 0)
        rf_f1  = rf.get("f1_score", 0)
        diff_acc = (ta - rf_acc) * 100
        diff_f1  = (tf1 - rf_f1) * 100
        sign_acc = "+" if diff_acc >= 0 else ""
        sign_f1  = "+" if diff_f1  >= 0 else ""
        print("\n  Model comparison:")
        print("             RF        LSTM")
        print("  Accuracy : {:.2f}%   {:.2f}%  ({}{:.2f}%)".format(
            rf_acc * 100, ta * 100, sign_acc, diff_acc))
        print("  F1 Score : {:.2f}%   {:.2f}%  ({}{:.2f}%)".format(
            rf_f1  * 100, tf1 * 100, sign_f1,  diff_f1))
    except Exception:
        pass

    print("\n  Saved files:")
    print("    " + LSTM_MODEL_PATH)
    print("    " + LSTM_META_PATH)
    print("    backend/models/lstm_evaluation.json")
    print("\n  Next step: python run.py")
    print("=" * 55)


if __name__ == "__main__":
    main()