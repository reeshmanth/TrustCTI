import pandas as pd
import numpy as np
import xgboost as xgb
from ml.features import extract_features, FEATURE_COLUMNS
from sklearn.model_selection import train_test_split

CLEAN_FEATURES = [f for f in FEATURE_COLUMNS if f not in {"abnormal_url", "//", "is_syntax_valid"}]

df = pd.read_csv("data/cti_binary_dataset.csv", usecols=CLEAN_FEATURES + ["is_malicious"])
X = df[CLEAN_FEATURES].astype(np.float32)
y = df["is_malicious"].astype(int).values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scale_pos_weight = float((y_train == 0).sum() / (y_train == 1).sum())

clf = xgb.XGBClassifier(
    n_estimators=150, max_depth=6, learning_rate=0.1, tree_method="hist",
    scale_pos_weight=scale_pos_weight, random_state=42, n_jobs=-1
)
clf.fit(X_train, y_train)

def test_url(u):
    feat = extract_features(u)
    sub_feat = {k: feat[k] for k in CLEAN_FEATURES}
    df_u = pd.DataFrame([sub_feat])[CLEAN_FEATURES].astype(np.float32)
    prob_mal = clf.predict_proba(df_u)[0, 1]
    print(f"URL: {u} -> Malicious Prob: {prob_mal:.4f} ({'MALICIOUS' if prob_mal >= 0.5 else 'BENIGN'})")

test_url("https://google.com")
test_url("https://github.com/torvalds/linux")
test_url("http://br-icloud.com.br")
test_url("http://adventure-nicaragua.net/index.php?option=com_mailto&tmpl=component&link=aHR0cD")
test_url("http://signin.eby.de.zukruygxctzmmqi.civpro.co.za")
test_url("http://192.168.1.100/admin/shell.php?cmd=whoami")

