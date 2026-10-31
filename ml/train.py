import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import xgboost as xgb
import shap

from ml.features import FEATURE_COLUMNS

DATASET_PATH = os.path.join("data", "cti_binary_dataset.csv")
ARTIFACTS_DIR = "artifacts"
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

CLASS_MAP = {
    "benign": 0,
    "defacement": 1,
    "phishing": 2,
    "malware": 3
}
INV_CLASS_MAP = {v: k for k, v in CLASS_MAP.items()}

def run_training():
    print("=" * 60)
    print("TrustCTI ML Pipeline: XGBoost Training & SHAP Integration")
    print("=" * 60)
    
    start_time = time.time()
    
    # 1. Load dataset
    print(f"Loading dataset from {DATASET_PATH}...")
    # Load required columns only to maximize speed and memory efficiency
    cols_to_load = FEATURE_COLUMNS + ["is_malicious", "class_label"]
    df = pd.read_csv(DATASET_PATH, usecols=cols_to_load)
    
    print(f"Dataset successfully loaded: {df.shape[0]:,} records, {len(FEATURE_COLUMNS)} input features.")
    
    # 2. Convert boolean or object types to float32
    X = df[FEATURE_COLUMNS].astype(np.float32)
    y_binary = df["is_malicious"].astype(int).values
    
    # Map class labels for multi-class classification
    y_multi = df["class_label"].str.lower().map(CLASS_MAP).fillna(0).astype(int).values
    
    print("\nClass distribution:")
    print("Binary Target (is_malicious):", dict(pd.Series(y_binary).value_counts()))
    print("Multi-Class Target (class_label):", {INV_CLASS_MAP[k]: v for k, v in pd.Series(y_multi).value_counts().items()})
    
    # 3. Stratified Train/Test Split (80% train, 20% test)
    print("\nSplitting into stratified Train (80%) and Test (20%) sets...")
    X_train, X_test, y_train, y_test, y_m_train, y_m_test = train_test_split(
        X, y_binary, y_multi,
        test_size=0.20,
        random_state=42,
        stratify=y_multi
    )
    print(f"Training samples: {X_train.shape[0]:,}")
    print(f"Testing samples:  {X_test.shape[0]:,}")
    
    # 4. Handle class imbalance
    neg_count = int((y_train == 0).sum())
    pos_count = int((y_train == 1).sum())
    scale_pos_weight = float(neg_count / max(pos_count, 1))
    print(f"Computed scale_pos_weight for imbalance handling: {scale_pos_weight:.4f}")
    
    # 5. Train Binary XGBoost Classifier
    print("\nTraining Binary XGBoost Classifier (Histogram method, multi-threaded)...")
    clf_binary = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        tree_method="hist",
        scale_pos_weight=scale_pos_weight,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )
    
    t_train_start = time.time()
    clf_binary.fit(X_train, y_train)
    t_train_end = time.time()
    print(f"Binary XGBoost trained in {t_train_end - t_train_start:.2f} seconds.")
    
    # 6. Evaluate Binary Model
    print("\nEvaluating Binary Model on Test Set...")
    y_pred = clf_binary.predict(X_test)
    y_prob = clf_binary.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {auc:.4f}")
    print("Confusion Matrix [[TN, FP], [FN, TP]]:", cm)
    
    # 7. Train Multi-Class Classifier for threat categorization
    print("\nTraining Multi-Class XGBoost Classifier for Threat Categorization...")
    clf_multi = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        tree_method="hist",
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=4,
        random_state=42,
        n_jobs=-1
    )
    clf_multi.fit(X_train, y_m_train)
    y_m_pred = clf_multi.predict(X_test)
    multi_acc = float(accuracy_score(y_m_test, y_m_pred))
    print(f"Multi-class accuracy: {multi_acc * 100:.2f}%")
    
    # 8. Fit SHAP TreeExplainer
    print("\nIntegrating SHAP TreeExplainer...")
    # Use 300 background samples for baseline expectation
    background_samples = X_train.sample(n=300, random_state=42)
    explainer = shap.TreeExplainer(clf_binary, background_samples)
    
    # Compute global feature importance using SHAP on a representative test batch
    print("Computing global feature importance using SHAP values (500 test samples)...")
    shap_test_sample = X_test.sample(n=500, random_state=42)
    shap_values = explainer.shap_values(shap_test_sample)
    
    mean_abs_shap = np.mean(np.abs(shap_values), axis=0)
    feature_importance = [
        {"feature": feat, "importance": float(imp)}
        for feat, imp in zip(FEATURE_COLUMNS, mean_abs_shap)
    ]
    feature_importance.sort(key=lambda x: x["importance"], reverse=True)
    
    print("\nTop 10 Most Influential Features (Global SHAP):")
    for rank, item in enumerate(feature_importance[:10], 1):
        print(f"  {rank}. {item['feature']}: {item['importance']:.4f}")
        
    # 9. Save Models and Metadata
    print("\nSaving trained artifacts...")
    joblib.dump(clf_binary, os.path.join(ARTIFACTS_DIR, "xgb_binary_model.joblib"))
    joblib.dump(clf_multi, os.path.join(ARTIFACTS_DIR, "xgb_multiclass_model.joblib"))
    joblib.dump(explainer, os.path.join(ARTIFACTS_DIR, "shap_explainer.joblib"))
    joblib.dump(background_samples, os.path.join(ARTIFACTS_DIR, "shap_background.joblib"))
    
    metrics = {
        "model_type": "XGBoost Classifier",
        "training_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "features_count": len(FEATURE_COLUMNS),
        "scale_pos_weight": scale_pos_weight,
        "evaluation": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "confusion_matrix": cm,
            "multi_class_accuracy": multi_acc
        },
        "target_mapping": CLASS_MAP,
        "training_duration_seconds": round(time.time() - start_time, 2),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
    
    with open(os.path.join(ARTIFACTS_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
        
    with open(os.path.join(ARTIFACTS_DIR, "feature_names.json"), "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
        
    with open(os.path.join(ARTIFACTS_DIR, "global_feature_importance.json"), "w") as f:
        json.dump(feature_importance, f, indent=2)
        
    print(f"\nAll artifacts saved successfully in '{ARTIFACTS_DIR}/' in {time.time() - start_time:.2f}s total.")
    return metrics

if __name__ == "__main__":
    run_training()

