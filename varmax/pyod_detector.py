import os
import sys
import time
import numpy as np
import pandas as pd
import json
import traceback
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import silhouette_score

# Import PyOD models
sys.path.append(os.path.abspath('models/pyod-master'))
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.knn import KNN
from pyod.models.ecod import ECOD
from pyod.models.hbos import HBOS
from pyod.models.combination import maximization, average, aom, moa
from sklearn.preprocessing import StandardScaler

# Threat types
THREAT_TYPES = {
    0: "Normal",
    1: "Anomaly",
    2: "Zero-Day"
}

# Model weights - higher weights for more reliable models
MODEL_WEIGHTS = {
    'iforest': 1.0,   # Very reliable for various datasets
    'lof': 0.8,       # Good for density-based detection
    'knn': 0.7,       # Good for clustered anomalies
    'hbos': 0.6,      # Fast but less precise
    'ecod': 0.9       # Good for high-dimensional data
}

def convert_to_serializable(obj):
    """
    Convert numpy types to native Python types for JSON serialization
    
    Args:
        obj: Object to convert
        
    Returns:
        JSON serializable object
    """
    if isinstance(obj, (np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.float64, np.float32, np.float16)):
        return float(obj)
    elif isinstance(obj, (np.bool_)):
        return bool(obj)
    elif isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {convert_to_serializable(k): convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_to_serializable(item) for item in obj)
    else:
        return obj

class PyODDetector:
    def __init__(self, model_dir='unified_model'):
        """
        Initialize the PyOD-based detector
        
        Args:
            model_dir: Directory containing model data
        """
        self.model_dir = model_dir
        self.dataset_stats = None
        self.models = {}
        self.scalers = {}
        self.model_weights = MODEL_WEIGHTS.copy()
        
        # Advanced parameters
        self.contamination = 0.1  # Default contamination level (expected anomaly ratio)
        self.ensemble_method = 'weighted'  # Ensemble combination method
        self.feature_importance_method = 'permutation'  # Method for feature importance
        self.min_confidence_threshold = 0.6  # Minimum confidence threshold for reporting anomalies
        
        # Initialize the detector
        self._initialize_detector()
        
    def _initialize_detector(self):
        """Initialize the detector with dataset stats and models"""
        try:
            # Load dataset statistics
            stats_path = os.path.join(self.model_dir, 'dataset_stats.joblib')
            if os.path.exists(stats_path):
                self.dataset_stats = joblib.load(stats_path)
                print(f"Loaded dataset statistics for {list(self.dataset_stats.keys())}")
            else:
                print(f"Dataset statistics file not found at {stats_path}")
                self.dataset_stats = {
                    'kdd': {'n_features': 41, 'n_classes': 5},
                    'train': {'n_features': 78, 'n_classes': 2},
                    'unsw': {'n_features': 44, 'n_classes': 10}
                }
                
            # Load scalers for each dataset
            for dataset_name in self.dataset_stats.keys():
                scaler_path = os.path.join(self.model_dir, f"{dataset_name}_scaler.joblib")
                if os.path.exists(scaler_path):
                    self.scalers[dataset_name] = joblib.load(scaler_path)
                    print(f"Loaded scaler for {dataset_name}")
                else:
                    print(f"Scaler for {dataset_name} not found at {scaler_path}")
                    # Create a new standard scaler
                    self.scalers[dataset_name] = StandardScaler()
                    
            # Initialize PyOD models for each dataset
            self.models = {}
            for dataset_name in self.dataset_stats.keys():
                # Create an ensemble of models with different parameters
                self.models[dataset_name] = {
                    # Isolation Forest with different configurations
                    'iforest': IForest(
                        n_estimators=100, 
                        contamination=self.contamination,
                        random_state=42,
                        max_features=0.8  # Use 80% of features for better generalization
                    ),
                    # LOF with different neighborhood sizes
                    'lof': LOF(
                        n_neighbors=20,
                        contamination=self.contamination,
                        algorithm='auto',
                        leaf_size=30,
                        metric='minkowski'
                    ),
                    # KNN with different parameters
                    'knn': KNN(
                        n_neighbors=5,
                        contamination=self.contamination,
                        method='largest',
                        radius=1.0,
                        algorithm='auto'
                    ),
                    # HBOS for fast histogram-based detection
                    'hbos': HBOS(
                        n_bins=10,
                        contamination=self.contamination,
                        alpha=0.1,
                        tol=0.5
                    ),
                    # ECOD for robust distribution-based detection
                    'ecod': ECOD(
                        contamination=self.contamination,
                    )
                }
                print(f"Initialized PyOD models for {dataset_name}")
                
        except Exception as e:
            print(f"Error initializing detector: {str(e)}")
            traceback.print_exc()
            
    def detect_threats(self, test_data, dataset_name=None, max_samples=100):
        """
        Detect threats in test data
        
        Args:
            test_data: Test data path or DataFrame
            dataset_name: Name of the dataset to use for detection
            max_samples: Maximum number of samples to analyze
            
        Returns:
            Dictionary with detection results
        """
        start_time = time.time()
        
        try:
            # Load test data
            if isinstance(test_data, str):
                print(f"Loading test data from {test_data}")
                try:
                    if os.path.exists(test_data):
                        df = pd.read_csv(test_data, nrows=max_samples)
                    else:
                        # Generate dummy data if file doesn't exist
                        print(f"Test data file {test_data} not found. Generating dummy data for interface testing.")
                        rows = max_samples
                        cols = 20  # Use 20 features for dummy data
                        df = pd.DataFrame(
                            np.random.rand(rows, cols),
                            columns=[f"feature_{i}" for i in range(cols)]
                        )
                        df['label'] = np.random.randint(0, 2, size=rows)
                except Exception as e:
                    return {"error": f"Failed to load test data: {str(e)}"}
            else:
                # Test data is already a DataFrame
                df = test_data.copy()
                if max_samples and len(df) > max_samples:
                    df = df.sample(max_samples, random_state=42)
            
            # Check if dataset has label column
            if 'label' not in df.columns:
                df['label'] = 0  # Default to normal
            
            # Get original feature names
            feature_names = [col for col in df.columns if col != 'label']
            print(f"Loaded test data with shape: {df.shape}")
            print(f"Test data has {len(feature_names)} features")
            
            # If dataset_name is not specified, try to infer from file name
            if dataset_name is None:
                if isinstance(test_data, str):
                    if 'kdd' in test_data.lower():
                        dataset_name = 'kdd'
                    elif 'unsw' in test_data.lower():
                        dataset_name = 'unsw'
                    else:
                        dataset_name = 'train'
            
            # If still None, use train as default
            if dataset_name is None:
                dataset_name = 'train'
            
            # Get expected number of features for this dataset
            n_features = self.dataset_stats.get(dataset_name, {}).get('n_features', len(feature_names))
            print(f"Dataset requires {n_features} features, padding with zeros")
            
            # Prepare input data (scale and pad)
            X, padded_feature_names = self._prepare_input(df.drop('label', axis=1), n_features, feature_names)
            
            # Run anomaly detection
            all_results = self._predict_anomalies(X, dataset_name, padded_feature_names)
            
            # Combine results and create final report
            predictions, feature_importance = self._combine_results(all_results)
            
            # Create a comprehensive report
            report = self._create_report(
                predictions, 
                df, 
                padded_feature_names, 
                dataset_name,
                start_time,
                feature_importance=feature_importance
            )
            
            return report
            
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}
    
    def _prepare_input(self, X, n_features, feature_names):
        """
        Prepare input data for prediction
        
        Args:
            X: Input data DataFrame
            n_features: Expected number of features
            feature_names: Original feature names
            
        Returns:
            Numpy array of prepared data and padded feature names
        """
        # Convert DataFrame to numpy array
        X_array = X.values
        
        # Create padded feature names
        padded_feature_names = list(feature_names)
        if n_features > X_array.shape[1]:
            # We need to pad with zeros
            padding = np.zeros((X_array.shape[0], n_features - X_array.shape[1]))
            X_padded = np.hstack((X_array, padding))
            
            # Add padding feature names
            for i in range(X_array.shape[1], n_features):
                padded_feature_names.append(f"padding_{i}")
        else:
            # We can use the data as is (or truncate if needed)
            X_padded = X_array[:, :n_features]
            padded_feature_names = padded_feature_names[:n_features]
        
        return X_padded, padded_feature_names
    
    def _predict_anomalies(self, X, dataset_name, feature_names):
        """
        Predict anomalies using multiple models
        
        Args:
            X: Input data
            dataset_name: Name of dataset
            feature_names: Feature names
            
        Returns:
            Dictionary with prediction results from all models
        """
        results = {}
        dataset_models = self.models.get(dataset_name, {})
        
        if not dataset_models:
            print(f"Warning: No models found for dataset {dataset_name}")
            # Create default models
            dataset_models = {
                'iforest': IForest(n_estimators=100, contamination=0.1, random_state=42),
                'lof': LOF(n_neighbors=20, contamination=0.1),
                'knn': KNN(n_neighbors=5, contamination=0.1, method='largest'),
                'hbos': HBOS(contamination=0.1),
                'ecod': ECOD(contamination=0.1)
            }
        
        # Get the scaler for this dataset
        scaler = self.scalers.get(dataset_name, StandardScaler())
        
        # Scale the data if we have a scaler
        if hasattr(scaler, 'transform'):
            try:
                X_scaled = scaler.transform(X)
            except:
                # Fit and transform if needed
                scaler.fit(X)
                X_scaled = scaler.transform(X)
        else:
            # No scaler available, use raw data
            X_scaled = X
        
        # Get model predictions
        for model_name, model in dataset_models.items():
            print(f"Fitting {model_name} model for {dataset_name}")
            try:
                # Fit the model
                model.fit(X_scaled)
                
                # Get anomaly scores
                scores = model.decision_scores_
                
                # Get binary predictions
                predictions = model.labels_
                
                # Get prediction confidence (normalized scores)
                min_score = np.min(scores)
                max_score = np.max(scores)
                confidence = np.zeros_like(scores)
                
                if max_score > min_score:
                    confidence = (scores - min_score) / (max_score - min_score)
                
                # Calculate feature importance
                feature_importance = self._get_feature_importance(
                    X_scaled, predictions, feature_names, model, method=self.feature_importance_method
                )
                
                # Store results
                results[model_name] = {
                    'scores': scores,
                    'predictions': predictions,
                    'confidence': confidence,
                    'feature_importance': feature_importance,
                    'weight': self.model_weights.get(model_name, 1.0)
                }
                
            except Exception as e:
                print(f"Error with {model_name} model: {str(e)}")
                # Add a placeholder for failed models
                results[model_name] = {
                    'scores': np.zeros(X.shape[0]),
                    'predictions': np.zeros(X.shape[0]),
                    'confidence': np.zeros(X.shape[0]),
                    'feature_importance': {},
                    'weight': 0.0  # Zero weight for failed models
                }
                traceback.print_exc()
        
        return results
    
    def _get_feature_importance(self, X_scaled, predictions, feature_names, model, method='permutation'):
        """
        Calculate feature importance for anomaly detection
        
        Args:
            X_scaled: Scaled input data
            predictions: Model predictions
            feature_names: Feature names
            model: The trained model
            method: Method for feature importance ('permutation', 'shap', or 'difference')
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        feature_importance = {}
        
        if method == 'permutation':
            # Permutation feature importance
            n_samples, n_features = X_scaled.shape
            baseline_score = np.mean(predictions)
            
            for i in range(n_features):
                if i >= len(feature_names):
                    continue
                    
                # Create a copy with one feature permuted
                X_permuted = X_scaled.copy()
                X_permuted[:, i] = np.random.permutation(X_permuted[:, i])
                
                # Get predictions with permuted feature
                try:
                    permuted_scores = model.decision_function(X_permuted)
                    permuted_preds = model.predict(X_permuted)
                    # Importance is the change in predictions
                    importance = np.abs(np.mean(permuted_preds) - baseline_score)
                    feature_importance[feature_names[i]] = float(importance)
                except:
                    # Some models don't have predict/decision_function
                    feature_importance[feature_names[i]] = 0.0
                    
        elif method == 'difference':
            # Simple difference between normal and anomaly feature distributions
            anomaly_idx = predictions == 1
            normal_idx = predictions == 0
            
            if np.any(anomaly_idx) and np.any(normal_idx):
                anomaly_means = np.mean(X_scaled[anomaly_idx], axis=0)
                normal_means = np.mean(X_scaled[normal_idx], axis=0)
                
                # Importance is absolute difference in means
                importance = np.abs(anomaly_means - normal_means)
                
                # Normalize to [0, 1]
                if np.max(importance) > 0:
                    importance = importance / np.max(importance)
                
                for i, feat_name in enumerate(feature_names):
                    if i < len(importance):
                        feature_importance[feat_name] = float(importance[i])
            else:
                # Equal importance if no anomalies or all anomalies
                equal_importance = 1.0 / len(feature_names)
                for feat_name in feature_names:
                    feature_importance[feat_name] = equal_importance
        else:
            # Default method
            equal_importance = 1.0 / len(feature_names)
            for feat_name in feature_names:
                feature_importance[feat_name] = equal_importance
                
        # Normalize feature importance
        if feature_importance:
            max_importance = max(feature_importance.values())
            if max_importance > 0:
                for feat, imp in feature_importance.items():
                    feature_importance[feat] = imp / max_importance
                
        return feature_importance
    
    def _combine_results(self, all_results):
        """
        Combine results from multiple models
        
        Args:
            all_results: Dictionary with results from all models
            
        Returns:
            Dictionary with combined predictions and feature importance
        """
        if not all_results:
            return {}, {}
        
        # Get number of samples from first model
        first_model = list(all_results.values())[0]
        n_samples = len(first_model['predictions'])
        
        # Initialize arrays for weighted voting
        weighted_scores = np.zeros(n_samples)
        total_weight = 0
        
        # For storing ensemble predictions
        ensemble_predictions = np.zeros(n_samples)
        ensemble_confidence = np.zeros(n_samples)
        
        # Combine model predictions using weighted voting
        for model_name, results in all_results.items():
            weight = results['weight']
            if weight <= 0:
                continue
                
            weighted_scores += results['scores'] * weight
            total_weight += weight
        
        # Normalize weighted scores
        if total_weight > 0:
            weighted_scores /= total_weight
            
            # Identify anomalies based on weighted scores
            # Dynamically determine threshold based on contamination level
            threshold = np.percentile(weighted_scores, 100 * (1 - self.contamination))
            ensemble_predictions = (weighted_scores > threshold).astype(int)
            
            # Calculate confidence scores (0 to 1)
            min_score = np.min(weighted_scores)
            max_score = np.max(weighted_scores)
            
            if max_score > min_score:
                ensemble_confidence = (weighted_scores - min_score) / (max_score - min_score)
            
        # Get feature importance by combining from all models
        feature_importance = {}
        
        # First, collect all feature names
        all_features = set()
        for results in all_results.values():
            all_features.update(results['feature_importance'].keys())
        
        # Combine feature importance using weighted average
        for feature in all_features:
            weighted_importance = 0
            feature_weight = 0
            
            for model_name, results in all_results.items():
                if feature in results['feature_importance'] and results['weight'] > 0:
                    weighted_importance += results['feature_importance'][feature] * results['weight']
                    feature_weight += results['weight']
            
            if feature_weight > 0:
                feature_importance[feature] = weighted_importance / feature_weight
            else:
                feature_importance[feature] = 0.0
        
        # Create final combined results
        combined_predictions = {
            'ensemble': {
                'predictions': ensemble_predictions,
                'confidence': ensemble_confidence
            }
        }
        
        # Add individual model predictions
        for model_name, results in all_results.items():
            combined_predictions[model_name] = {
                'predictions': results['predictions'],
                'confidence': results['confidence']
            }
        
        return combined_predictions, feature_importance
    
    def _create_report(self, predictions, df, feature_names, dataset_name, start_time, feature_importance=None):
        """
        Create a comprehensive analysis report
        
        Args:
            predictions: Dictionary with model predictions
            df: Original DataFrame
            feature_names: Feature names
            dataset_name: Name of dataset
            start_time: Start time of analysis
            feature_importance: Dictionary with feature importance
            
        Returns:
            Dictionary with analysis report
        """
        # Extract ensemble predictions
        ensemble_predictions = predictions.get('ensemble', {}).get('predictions', np.zeros(len(df)))
        ensemble_confidence = predictions.get('ensemble', {}).get('confidence', np.zeros(len(df)))
        
        # Count by prediction type
        counts = {
            'Normal': int(np.sum(ensemble_predictions == 0)),
            'Anomaly': int(np.sum(ensemble_predictions == 1)),
            'Zero-Day': 0  # Will be determined later
        }
        
        # Initialize threat list
        threats = []
        detailed_threats = []
        
        # Define a threshold for confidence to report threats
        confidence_threshold = self.min_confidence_threshold
        
        # Process each record
        for i in range(len(df)):
            # Skip normal traffic with high confidence
            if ensemble_predictions[i] == 0 and ensemble_confidence[i] < 0.3:
                continue
                
            # Get base prediction
            is_anomaly = ensemble_predictions[i] == 1
            
            # Check for model disagreement (potential zero-day threats)
            model_predictions = {}
            prediction_disagreement = False
            
            # Get predictions from each model
            for model_name, model_preds in predictions.items():
                if model_name == 'ensemble':
                    continue
                    
                pred = int(model_preds['predictions'][i])
                conf = float(model_preds['confidence'][i])
                model_predictions[model_name] = {'prediction': pred, 'confidence': conf}
                
                # Look for high-confidence disagreements
                if model_name != 'ensemble' and conf > 0.7:
                    if (pred == 1 and not is_anomaly) or (pred == 0 and is_anomaly):
                        prediction_disagreement = True
            
            # Determine threat type
            if prediction_disagreement:
                threat_type = 'Zero-Day'
                counts['Zero-Day'] += 1
                # Adjust anomaly count
                if is_anomaly:
                    counts['Anomaly'] -= 1
            elif is_anomaly:
                threat_type = 'Anomaly'
            else:
                # Skip normal traffic
                continue
            
            # Calculate severity (combine confidence with feature importance)
            severity = ensemble_confidence[i]
            
            # Add more weight if there are important features
            if feature_importance:
                # Get record features
                record_features = {}
                for j, feat_name in enumerate(feature_names):
                    if j < len(df.columns) - 1:  # Exclude label
                        record_features[feat_name] = df.iloc[i, j]
                
                # Calculate a weighted severity based on feature importance
                weighted_severity = 0
                total_weight = 0
                
                for feat, value in record_features.items():
                    if feat in feature_importance:
                        imp = feature_importance[feat]
                        weighted_severity += abs(value) * imp
                        total_weight += imp
                
                if total_weight > 0:
                    weighted_severity /= total_weight
                    # Combine with confidence
                    severity = 0.7 * severity + 0.3 * weighted_severity
            
            # Generate record features for the report
            record_data = {}
            record_feature_importance = {}
            
            for j, feat_name in enumerate(feature_names):
                if j < len(df.columns) - 1:  # Exclude label
                    feat_value = df.iloc[i, j]
                    record_data[feat_name] = feat_value
                    
                    # Add feature importance
                    if feature_importance and feat_name in feature_importance:
                        record_feature_importance[feat_name] = feature_importance[feat_name]
            
            # Basic threat info for the summary
            threat_info = {
                'id': i + 1,
                'type': threat_type,
                'confidence': float(ensemble_confidence[i]),
                'severity': float(severity),
                'feature_importance': record_feature_importance,
                'model_predictions': model_predictions
            }
            
            threats.append(threat_info)
            
            # Detailed threat info with full record data
            detailed_info = threat_info.copy()
            detailed_info['record'] = record_data
            detailed_threats.append(detailed_info)
        
        # Determine risk assessment
        risk_assessment = "LOW RISK - No Anomalies Detected"
        if counts['Zero-Day'] > 0:
            if counts['Zero-Day'] > 5:
                risk_assessment = "CRITICAL RISK - Multiple Zero-Day Threats Detected"
            else:
                risk_assessment = "HIGH RISK - Zero-Day Threat Detected"
        elif counts['Anomaly'] > 10:
            risk_assessment = "HIGH RISK - Multiple Anomalies Detected"
        elif counts['Anomaly'] > 0:
            risk_assessment = "MEDIUM RISK - Multiple Anomalies Detected"
        
        # Analysis metadata
        analysis_time = time.time() - start_time
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create the final report
        report = {
            "success": True,
            "metadata": {
                "dataset_name": dataset_name,
                "timestamp": timestamp,
                "analysis_time": analysis_time,
                "total_records": len(df),
                "features_analyzed": len(feature_names)
            },
            "threat_distribution": {
                "counts": counts,
                "percentages": {
                    "Normal": counts["Normal"] / len(df) * 100 if len(df) > 0 else 0,
                    "Anomaly": counts["Anomaly"] / len(df) * 100 if len(df) > 0 else 0,
                    "Zero-Day": counts["Zero-Day"] / len(df) * 100 if len(df) > 0 else 0
                }
            },
            "risk_assessment": risk_assessment,
            "threats": threats,
            "detailed_threats": detailed_threats
        }
        
        return report
    
    def save_results(self, results, output_dir="results"):
        """
        Save analysis results to file
        
        Args:
            results: Analysis results dictionary
            output_dir: Output directory
            
        Returns:
            Path to saved file
        """
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate a timestamp for the filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(f"analysis_{timestamp}.json")
            
            # Convert results to JSON
            json_results = convert_to_serializable(results)
            
            # Save to file
            with open(output_file, 'w') as f:
                json.dump(json_results, f, indent=2)
                
            print(f"Saved analysis results to {output_file}")
            return output_file
            
        except Exception as e:
            print(f"Error saving results: {str(e)}")
            traceback.print_exc()
            return None

def main():
    """Main function for testing"""
    from argparse import ArgumentParser
    
    parser = ArgumentParser(description="PyOD-based Anomaly Detector")
    parser.add_argument("--data", type=str, required=True, help="Path to test data CSV file")
    parser.add_argument("--dataset", type=str, default="unsw", help="Dataset type (kdd, train, unsw)")
    parser.add_argument("--samples", type=int, default=100, help="Number of samples to analyze")
    parser.add_argument("--contamination", type=float, default=0.1, help="Expected anomaly ratio")
    parser.add_argument("--threshold", type=float, default=0.6, help="Confidence threshold")
    
    args = parser.parse_args()
    
    detector = PyODDetector(model_dir='unified_model')
    
    # Set advanced parameters
    detector.contamination = args.contamination
    detector.min_confidence_threshold = args.threshold
    
    results = detector.detect_threats(
        test_data=args.data,
        dataset_name=args.dataset,
        max_samples=args.samples
    )
    
    # Save results
    detector.save_results(results)
    
    # Print summary
    if "threat_distribution" in results:
        counts = results["threat_distribution"]["counts"]
        print("\nDetection Summary:")
        print(f"Normal:   {counts.get('Normal', 0)}")
        print(f"Anomaly:  {counts.get('Anomaly', 0)}")
        print(f"Zero-Day: {counts.get('Zero-Day', 0)}")
        print(f"\nRisk Assessment: {results.get('risk_assessment', 'Unknown')}")
    
if __name__ == "__main__":
    main() 