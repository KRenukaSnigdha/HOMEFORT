import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nsl_kdd_preprocessed.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'label_encoder.joblib')

# ---------------- LOAD DATA ----------------
df = pd.read_csv(DATA_PATH)

# Features must match realtime_detect.py
features = ['protocol_type', 'src_bytes', 'dst_bytes']

# Encode protocol_type
le_proto = LabelEncoder()
df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])

# Encode labels
label_le = LabelEncoder()
df['label'] = label_le.fit_transform(df['label'])

X = df[features]
y = df['label']

# ---------------- STRATIFIED SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------------- TRAIN MODEL ----------------
clf = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

clf.fit(X_train, y_train)

# ---------------- EVALUATE ----------------
print("Training complete. Evaluating...")
y_pred = clf.predict(X_test)

print(classification_report(y_test, y_pred, zero_division=0))

# ---------------- SAVE ----------------
os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'models'), exist_ok=True)

joblib.dump(clf, MODEL_PATH)
joblib.dump(le_proto, PROTO_ENCODER_PATH)
joblib.dump(label_le, LABEL_ENCODER_PATH)

print(f"Model saved to {MODEL_PATH}")
print(f"Protocol encoder saved to {PROTO_ENCODER_PATH}")
print(f"Label encoder saved to {LABEL_ENCODER_PATH}")
