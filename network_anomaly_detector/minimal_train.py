import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest

print('Training minimal model...')
df = pd.read_csv('data/generated_logs/logs.csv')
features = df[['bytes_sent', 'bytes_received', 'duration', 'packets']].values
model = IsolationForest(contamination=0.05)
model.fit(features)
os.makedirs('data/trained_models', exist_ok=True)
joblib.dump(model, 'data/trained_models/anomaly_model.pkl')
print('Model saved!')
