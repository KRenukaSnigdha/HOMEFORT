import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nsl_kdd_preprocessed.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')

# Load data
df = pd.read_csv(DATA_PATH)

# Use only features available in real time
features = ['protocol_type', 'src_bytes', 'dst_bytes']

# Encode protocol_type
le_proto = LabelEncoder()
df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])

# Encode label column
label_le = LabelEncoder()
df['label'] = label_le.fit_transform(df['label'])

X = df[features]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print('Training complete. Evaluating...')
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(clf, MODEL_PATH)
print(f'Model saved to {MODEL_PATH}')
# Save protocol_type encoder for use in real-time detection
joblib.dump(le_proto, os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')) 