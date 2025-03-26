import pandas as pd
import numpy as np
import os
import joblib
import traceback
from sklearn.ensemble import IsolationForest

try:
    print("Starting simple training script...")
    
    # Define paths
    data_path = 'data/generated_logs/logs.csv'
    model_path = 'data/trained_models/simple_model.pkl'
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Load data
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"Loaded {len(df)} records")
    
    # Select only numeric features for simplicity
    features = df[['bytes_sent', 'bytes_received', 'duration', 'packets']].values
    print(f"Feature shape: {features.shape}")
    
    # Train a simple model
    print("Training model...")
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    
    # Save the model
    print(f"Saving model to {model_path}")
    joblib.dump(model, model_path)
    print("Done!")
    
except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc() 