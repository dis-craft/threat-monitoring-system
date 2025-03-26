import numpy as np
import torch
import time
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN
import joblib
import os
from tqdm import tqdm

class AnomalyDetectionModule:
    def __init__(self, device="cpu", save_path="models"):
        self.device = device
        self.save_path = save_path
        self.detectors = {}
        os.makedirs(save_path, exist_ok=True)
    
    def train_anomaly_detectors(self, X_train_scaled):
        """Train multiple anomaly detection models and save them"""
        print("\n🔧 Training Anomaly Detectors")
        
        # Limit sample size for training efficiency
        sample_size = min(100000, X_train_scaled.shape[0])
        X_sample = X_train_scaled[:sample_size]
        
        print(f"Training on {X_sample.shape[0]:,} samples...")
        
        # Train Isolation Forest
        print("▶ Training Isolation Forest...")
        start_time = time.time()
        self.detectors['isolation_forest'] = IsolationForest(
            contamination=0.01,
            n_estimators=100,
            verbose=1,
            n_jobs=-1
        ).fit(X_sample)
        print(f"Completed in {time.time()-start_time:.1f}s")

        # Train One-Class SVM
        print("▶ Training One-Class SVM...")
        start_time = time.time()
        self.detectors['one_class_svm'] = OneClassSVM(
            nu=0.01,
            kernel='rbf',
            max_iter=5000,
            tol=1e-4,
            verbose=True
        ).fit(X_sample)
        print(f"Completed in {time.time()-start_time:.1f}s")

        # Train Local Outlier Factor
        print("▶ Training LOF...")
        start_time = time.time()
        self.detectors['lof'] = LocalOutlierFactor(
            novelty=True,
            n_neighbors=20,
            n_jobs=-1
        ).fit(X_sample)
        print(f"Completed in {time.time()-start_time:.1f}s")
        
        # Save the anomaly detectors
        detector_path = os.path.join(self.save_path, "anomaly_detectors.joblib")
        joblib.dump(self.detectors, detector_path)
        print(f"Anomaly detectors saved to: {detector_path}")
        
        return self.detectors
    
    def load_anomaly_detectors(self, path=None):
        """Load trained anomaly detection models"""
        if path is None:
            path = os.path.join(self.save_path, "anomaly_detectors.joblib")
        
        if os.path.exists(path):
            self.detectors = joblib.load(path)
            print(f"Loaded anomaly detectors from: {path}")
            return True
        else:
            print(f"No anomaly detectors found at: {path}")
            return False
    
    def predict_anomalies(self, X_data, threshold=-0.5):
        """Predict anomalies using the ensemble of detectors"""
        if not self.detectors:
            raise ValueError("No anomaly detectors available. Train or load detectors first.")
        
        results = {}
        for name, detector in self.detectors.items():
            if name == 'dbscan':
                # DBSCAN doesn't have a predict method, use fit_predict instead
                labels = detector.fit_predict(X_data)
                results[name] = np.where(labels == -1, 1, 0)  # 1 for anomalies, 0 for normal
            else:
                # For other detectors, use predict
                scores = detector.predict(X_data)
                results[name] = np.where(scores <= threshold, 1, 0)  # 1 for anomalies, 0 for normal
        
        # Combine results (majority voting)
        ensemble_results = np.zeros(X_data.shape[0])
        for name, preds in results.items():
            ensemble_results += preds
        
        # If more than half of detectors flag as anomaly, consider it an anomaly
        anomaly_mask = ensemble_results >= len(self.detectors) / 2
        return anomaly_mask 