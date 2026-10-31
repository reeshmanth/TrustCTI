import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb

from ml.features import FEATURE_COLUMNS

# Exclude non-reproducible leakage columns
CLEAN_FEATURES = [f for f in FEATURE_COLUMNS if f not in {"abnormal_url", "//", "is_syntax_valid"}]
print(f"Testing with {len(CLEAN_FEATURES)} purely reproducible features...")

df = pd.read_csv("data/cti_binary_dataset.csv", usecols=CLEAN_FEATURES + ["is_malicious"])

X = df[CLEAN_FEATURES].astype(np.float32)
y = df["is_malicious"].astype(int).values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scale_pos_weight = float((y_train == 0).sum() / (y_train == 1).sum())

clf = xgb.XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    tree_method="hist",
    scale_pos_weight=scale_pos_weight,
    random_state=42,
    n_jobs=-1
)

clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print("Clean Model Performance:")
print(f"Accuracy:  {accuracy_score(y_test, y_pred) * 100:.2f}%")
print(f"Precision: {precision_score(y_test, y_pred) * 100:.2f}%")
print(f"Recall:    {recall_score(y_test, y_pred) * 100:.2f}%")
print(f"F1-Score:  {f1_score(y_test, y_pred) * 100:.2f}%")
print(f"ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")

