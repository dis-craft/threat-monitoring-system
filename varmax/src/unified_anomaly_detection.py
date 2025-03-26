import numpy as np
import torch
import time
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
import joblib
import os
from tqdm import tqdm

class UnifiedAnomalyDetector:
    def __init__(self, model, device="cpu", save_path="models/unified"):
        """
        Unified anomaly detector that works with unified model across all datasets
        
        Args:
            model: The UnifiedVarMaxModel instance
            device: Device to use
            save_path: Path to save the detectors
        """
        self.model = model
        self.device = device
        self.save_path = save_path
        self.detectors = {}
        os.makedirs(save_path, exist_ok=True)
    
    def train_anomaly_detectors(self, dataloaders, use_feature_extraction=True):
        """
        Train anomaly detectors for each dataset
        
        Args:
            dataloaders: Dict of {dataset_name: {'train': train_loader, ...}}
            use_feature_extraction: Whether to use features from model or raw inputs
            
        Returns:
            Dict of trained anomaly detectors
        """
        print("\n🔍 Training Unified Anomaly Detection System")
        
        # Set model to eval mode for feature extraction
        self.model.eval()
        
        # Train detectors for each dataset
        for dataset_name, loaders in dataloaders.items():
            print(f"\n📊 Training anomaly detectors for {dataset_name}")
            train_loader = loaders['train']
            
            # Extract features or get raw inputs
            if use_feature_extraction:
                # Extract features using the model's feature extractor
                features = []
                with torch.no_grad():
                    for inputs, _ in tqdm(train_loader, desc=f"Extracting features for {dataset_name}"):
                        inputs = inputs.to(self.device)
                        # Use the get_features method to extract intermediate representations
                        batch_features = self.model.get_features(inputs, dataset_name).cpu().numpy()
                        features.append(batch_features)
                
                if features:
                    X_train = np.vstack(features)
                else:
                    print(f"⚠️ No features extracted for {dataset_name}")
                    continue
            else:
                # Use raw inputs
                X_train = []
                for inputs, _ in tqdm(train_loader, desc=f"Processing inputs for {dataset_name}"):
                    X_train.append(inputs.numpy())
                
                if X_train:
                    X_train = np.vstack(X_train)
                else:
                    print(f"⚠️ No inputs processed for {dataset_name}")
                    continue
            
            # Limit sample size for training efficiency if needed
            sample_size = min(50000, X_train.shape[0])
            X_sample = X_train[:sample_size]
            
            print(f"Training on {X_sample.shape[0]:,} samples with {X_sample.shape[1]} features")
            
            # Initialize detectors for this dataset
            self.detectors[dataset_name] = {}
            
            # Train Isolation Forest
            print("▶ Training Isolation Forest...")
            start_time = time.time()
            self.detectors[dataset_name]['isolation_forest'] = IsolationForest(
                contamination=0.01,
                n_estimators=100,
                n_jobs=-1
            ).fit(X_sample)
            print(f"Completed in {time.time()-start_time:.1f}s")
            
            # Train One-Class SVM
            print("▶ Training One-Class SVM...")
            start_time = time.time()
            self.detectors[dataset_name]['one_class_svm'] = OneClassSVM(
                nu=0.01,
                kernel='rbf',
                gamma='scale'
            ).fit(X_sample)
            print(f"Completed in {time.time()-start_time:.1f}s")
            
            # Train Local Outlier Factor
            print("▶ Training LOF...")
            start_time = time.time()
            self.detectors[dataset_name]['lof'] = LocalOutlierFactor(
                novelty=True,
                n_neighbors=20,
                n_jobs=-1
            ).fit(X_sample)
            print(f"Completed in {time.time()-start_time:.1f}s")
            
        # Save all detectors
        detector_path = os.path.join(self.save_path, "unified_anomaly_detectors.joblib")
        joblib.dump(self.detectors, detector_path)
        print(f"\n✅ All anomaly detectors saved to: {detector_path}")
        
        return self.detectors
    
    def load_anomaly_detectors(self, path=None):
        """Load trained anomaly detectors"""
        if path is None:
            path = os.path.join(self.save_path, "unified_anomaly_detectors.joblib")
        
        if os.path.exists(path):
            self.detectors = joblib.load(path)
            print(f"Loaded anomaly detectors from: {path}")
            return True
        else:
            print(f"No anomaly detectors found at: {path}")
            return False
    
    def predict_anomalies(self, inputs, dataset_name, use_feature_extraction=True, threshold=-0.5):
        """
        Predict anomalies for inputs from a specific dataset
        
        Args:
            inputs: Tensor of input features
            dataset_name: Name of the dataset
            use_feature_extraction: Whether to use features from model or raw inputs
            threshold: Threshold for anomaly detection
            
        Returns:
            Boolean mask of anomalies (True for anomalies)
        """
        if dataset_name not in self.detectors:
            raise ValueError(f"No detectors found for dataset {dataset_name}")
        
        # Extract features or use raw inputs
        if use_feature_extraction:
            with torch.no_grad():
                inputs = inputs.to(self.device)
                X_data = self.model.get_features(inputs, dataset_name).cpu().numpy()
        else:
            X_data = inputs.numpy()
        
        # Predict with each detector
        results = {}
        for name, detector in self.detectors[dataset_name].items():
            # Use predict for novelty detection
            scores = detector.predict(X_data)
            results[name] = np.where(scores <= threshold, 1, 0)  # 1 for anomalies
        
        # Combine results (majority voting)
        ensemble_results = np.zeros(X_data.shape[0])
        for name, preds in results.items():
            ensemble_results += preds
        
        # If more than half of detectors flag as anomaly, consider it an anomaly
        anomaly_mask = ensemble_results >= len(self.detectors[dataset_name]) / 2
        return anomaly_mask
    
    def get_varmax_scores(self, dataloaders):
        """
        Compute VarMax scores for all datasets
        
        Args:
            dataloaders: Dict of {dataset_name: {'test': test_loader}}
            
        Returns:
            Dict of {dataset_name: {'scores': scores, 'labels': labels}}
        """
        results = {}
        self.model.eval()
        
        for dataset_name, loaders in dataloaders.items():
            test_loader = loaders['test']
            scores = []
            labels = []
            
            with torch.no_grad():
                for inputs, true_labels in tqdm(test_loader, desc=f"Computing VarMax scores for {dataset_name}"):
                    inputs = inputs.to(self.device)
                    
                    # Get logits
                    logits = self.model(inputs, dataset_name)
                    logits_np = logits.cpu().numpy()
                    
                    # Compute variance of absolute logits for each sample
                    for i in range(inputs.size(0)):
                        variance = np.var(np.abs(logits_np[i]))
                        scores.append(variance)
                    
                    # Store true labels
                    labels.extend(true_labels.cpu().numpy())
            
            results[dataset_name] = {
                'scores': scores,
                'labels': labels
            }
            
            # Print summary statistics
            scores_array = np.array(scores)
            print(f"\nVarMax Score Statistics for {dataset_name}:")
            print(f"- Mean: {scores_array.mean():.4f}")
            print(f"- Std Dev: {scores_array.std():.4f}")
            print(f"- Min: {scores_array.min():.4f}")
            print(f"- Max: {scores_array.max():.4f}")
        
        return results 