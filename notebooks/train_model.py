import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

# Load dataset
df = pd.read_csv("../data/cicids2017.csv")

# ✅ SELECT ONLY REALISTIC FEATURES
selected_features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Flow Bytes/s',
    'Packet Length Mean',
    'ACK Flag Count'
]

X = df[selected_features]
y = df['Attack Type']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train_scaled, y_train)

# Save
joblib.dump(model, "../models/nids_model_limited.pkl")
joblib.dump(scaler, "../models/scaler_limited.pkl")

print("✅ Model trained and saved!")