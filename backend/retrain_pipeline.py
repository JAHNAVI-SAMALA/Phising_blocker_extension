"""
Incremental model retraining pipeline.
Called automatically when new community-reported phishing sites hit threshold.
"""
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import os
import threading

from feature_extractor import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'phishing_model.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'models', 'feature_names.pkl')

_retrain_lock = threading.Lock()

def retrain_with_new_data(new_reports):
    """
    new_reports: list of dicts with keys: url, features (JSON str), label
    Performs incremental retraining and saves updated model.
    Returns dict with accuracy metrics.
    """
    if not _retrain_lock.acquire(blocking=False):
        return {"status": "already_retraining", "skipped": True}

    try:
        print(f"[~] Starting retraining with {len(new_reports)} new samples...")
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

        # Load existing model if present
        existing_model = None
        feature_names = None
        if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
            existing_model = joblib.load(MODEL_PATH)
            feature_names = joblib.load(FEATURES_PATH)

        # Build dataset from new reports
        rows = []
        for r in new_reports:
            try:
                feats = json.loads(r['features']) if isinstance(r['features'], str) else r['features']
                if not feats:
                    feats = extract_features(r['url'])
                feats['label'] = int(r.get('label', 1))
                rows.append(feats)
            except Exception:
                continue

        if not rows:
            return {"status": "no_valid_samples"}

        df = pd.DataFrame(rows)
        if feature_names:
            # Align columns
            for col in feature_names:
                if col not in df.columns:
                    df[col] = 0
            X_new = df[feature_names]
        else:
            feature_names = [c for c in df.columns if c != 'label']
            X_new = df[feature_names]

        y_new = df['label']

        # Add some legit samples to balance classes
        legit_urls = [
            "https://www.google.com", "https://github.com",
            "https://stackoverflow.com", "https://www.amazon.com",
            "https://www.microsoft.com", "https://www.linkedin.com",
        ]
        for url in legit_urls:
            feats = extract_features(url)
            feats['label'] = 0
            for col in feature_names:
                if col not in feats:
                    feats[col] = 0
            rows.append(feats)

        df_full = pd.DataFrame(rows)
        for col in feature_names:
            if col not in df_full.columns:
                df_full[col] = 0

        X = df_full[feature_names]
        y = df_full['label']

        # Split
        if len(X) < 10:
            X_train, X_test, y_train, y_test = X, X, y, y
        else:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42)

        # Measure accuracy before
        acc_before = 0.5
        if existing_model and len(X_test) > 0:
            try:
                probs = existing_model.predict_proba(X_test)[:, 1]
                acc_before = roc_auc_score(y_test, probs) if len(set(y_test)) > 1 else 0.5
            except Exception:
                pass

        # Retrain fresh model (for hackathon; production would use warm_start)
        model = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=4,
                random_state=42,
                warm_start=False
            ))
        ])
        model.fit(X_train, y_train)

        # Measure accuracy after
        acc_after = 0.5
        if len(X_test) > 0 and len(set(y_test)) > 1:
            try:
                probs = model.predict_proba(X_test)[:, 1]
                acc_after = roc_auc_score(y_test, probs)
            except Exception:
                pass

        # Save updated model
        joblib.dump(model, MODEL_PATH)
        joblib.dump(feature_names, FEATURES_PATH)

        print(f"[OK] Retraining complete. AUC: {acc_before:.3f} -> {acc_after:.3f}")

        # Log to DB
        try:
            from db.database import log_retrain
            log_retrain(len(new_reports), acc_before, acc_after, 'done')
        except Exception:
            pass

        return {
            "status": "success",
            "new_samples": len(new_reports),
            "auc_before": round(acc_before, 4),
            "auc_after": round(acc_after, 4),
            "improvement": round(acc_after - acc_before, 4)
        }

    except Exception as e:
        print(f"[ERROR] Retraining failed: {e}")
        return {"status": "error", "error": str(e)}
    finally:
        _retrain_lock.release()


def async_retrain(new_reports):
    """Non-blocking retrain in background thread."""
    t = threading.Thread(target=retrain_with_new_data, args=(new_reports,), daemon=True)
    t.start()
    return {"status": "retraining_started", "samples": len(new_reports)}
