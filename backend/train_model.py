import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import os

def train():
    CSV_PATH = 'dataset_full.csv'
    
    print("📂 Loading dataset...")
    df = pd.read_csv(CSV_PATH)
    print(f"Total rows: {len(df)}")

    # ── Fix: this dataset uses 'legitimate'/'phishing' not 0/1 ──
    df['status'] = df['status'].map({'legitimate': 0, 'phishing': 1})
    df = df.dropna(subset=['status'])

    # ── This dataset already HAS features — no need to extract ──
    # Drop the url column, use everything else as features
    DROP_COLS = ['url', 'status']
    feature_cols = [c for c in df.columns if c not in DROP_COLS]

    X = df[feature_cols]
    y = df['status'].astype(int)

    print(f"✅ {len(df)} rows — {y.sum()} phishing, {(y==0).sum()} legit")
    print(f"✅ {len(feature_cols)} features ready")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    model = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        ))
    ])

    print("\n🚀 Training model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n📈 Model Performance:")
    print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    cv_scores = cross_val_score(model, X, y, cv=5, scoring='roc_auc')
    print(f"\n5-Fold CV AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/phishing_model.pkl')
    joblib.dump(feature_cols, 'models/feature_names.pkl')
    print("\n✅ Model saved to models/phishing_model.pkl")

    return model, feature_cols

if __name__ == '__main__':
    train()