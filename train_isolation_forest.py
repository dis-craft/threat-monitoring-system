import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from config import DATA_PATH, MODEL_PATH, SCALER_PATH

def train_model():
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    
    # Load and preprocess data
    print("Loading data...")
    df = pd.read_csv(DATA_PATH)
    normal_traffic = df[df['dst_port'] != 31337]  # Filter out known anomalies
    
    # Preprocessing pipeline
    print("Preprocessing data...")
    numeric_features = ['bytes_sent', 'bytes_received', 'duration', 'packets']
    categorical_features = ['protocol', 'tcp_flags', 'http_status']
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ])
    
    # Create an isolation forest model pipeline
    print("Training Isolation Forest model...")
    model = Pipeline([
        ('preprocessor', preprocessor),
        ('isolation_forest', IsolationForest(contamination=0.05, random_state=42))
    ])
    
    # Fit the model on normal traffic only
    model.fit(normal_traffic[numeric_features + categorical_features])
    
    # Save the model
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    print("Model training completed successfully!")

if __name__ == '__main__':
    train_model() 