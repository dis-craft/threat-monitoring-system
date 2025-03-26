import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
import joblib
import json
import time
import argparse
from datetime import datetime
import shap
import matplotlib.pyplot as plt
import traceback

# Threat types
THREAT_TYPES = {
    0: "Normal",
    1: "Anomaly",
    2: "Zero-Day"
}

def convert_to_serializable(obj):
    """
    Convert numpy types to native Python types for JSON serialization
    
    Args:
        obj: Object to convert
        
    Returns:
        JSON serializable object
    """
    if isinstance(obj, (np.int_, np.intc, np.intp, np.int8, np.int16, np.int32, np.int64,
                         np.uint8, np.uint16, np.uint32, np.uint64)):
        return int(obj)
    elif isinstance(obj, (np.float64, np.float16, np.float32, np.float64)):
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

class UnifiedAnomalyDetector:
    def __init__(self, model_dir='unified_model'):
        """
        Unified Anomaly Detector that combines multiple models
        
        Args:
            model_dir: Directory with trained models
        """
        self.model_dir = model_dir
        
        # Load dataset statistics
        stats_path = os.path.join(model_dir, "dataset_stats.joblib")
        if not os.path.exists(stats_path):
            raise FileNotFoundError(f"Dataset statistics not found at {stats_path}. Please train the model first.")
        
        self.dataset_stats = joblib.load(stats_path)
        print(f"Loaded dataset statistics for {list(self.dataset_stats.keys())}")
        
        # Load models and scalers
        self.models = {}
        self.scalers = {}
        self.iso_forests = {}
        
        for dataset_name in self.dataset_stats.keys():
            try:
                # Load the keras model
                model_path = os.path.join(model_dir, f"{dataset_name}_model.h5")
                if os.path.exists(model_path):
                    self.models[dataset_name] = load_model(model_path)
                    print(f"Loaded model for {dataset_name}")
                else:
                    print(f"Model for {dataset_name} not found at {model_path}")
                    
                # Load the scaler
                scaler_path = os.path.join(model_dir, f"{dataset_name}_scaler.joblib")
                if os.path.exists(scaler_path):
                    self.scalers[dataset_name] = joblib.load(scaler_path)
                    print(f"Loaded scaler for {dataset_name}")
                else:
                    print(f"Scaler for {dataset_name} not found at {scaler_path}")
                    
                # Load the isolation forest
                iso_path = os.path.join(model_dir, f"{dataset_name}_isoforest.joblib")
                if os.path.exists(iso_path):
                    self.iso_forests[dataset_name] = joblib.load(iso_path)
                    print(f"Loaded isolation forest for {dataset_name}")
                else:
                    print(f"Isolation forest for {dataset_name} not found at {iso_path}")
            except Exception as e:
                print(f"Error loading models for {dataset_name}: {str(e)}")
                # Continue with other datasets if one fails
    
    def explain_prediction(self, X, dataset_name, feature_names=None):
        """
        Explain prediction using SHAP values
        
        Args:
            X: Input features (scaled)
            dataset_name: Name of the dataset
            feature_names: Feature names
            
        Returns:
            Dictionary with feature importance
        """
        try:
            if dataset_name not in self.models:
                return {}
            
            # Get expected feature count for this model
            expected_features = self.dataset_stats[dataset_name]['n_features']
            actual_features = X.shape[1]
            
            # Get feature names
            if feature_names is None or len(feature_names) != actual_features:
                if dataset_name in self.dataset_stats and 'feature_names' in self.dataset_stats[dataset_name]:
                    feature_names = self.dataset_stats[dataset_name]['feature_names'][:actual_features]
                else:
                    feature_names = [f"feature_{i}" for i in range(actual_features)]
                
            # Ensure we have the correct number of feature names
            if len(feature_names) > actual_features:
                feature_names = feature_names[:actual_features]
            elif len(feature_names) < actual_features:
                feature_names.extend([f"feature_{i+len(feature_names)}" for i in range(actual_features - len(feature_names))])
                
            # Try using SHAP for explanation
            try:
                # Create a function that returns the model predictions
                def model_predict(x):
                    # Handle dimensionality issues
                    if x.shape[1] != expected_features:
                        if x.shape[1] < expected_features:
                            # Pad with zeros
                            padding = np.zeros((x.shape[0], expected_features - x.shape[1]))
                            x_padded = np.hstack((x, padding))
                            return self.models[dataset_name].predict(x_padded)
                        else:
                            # Select first features
                            return self.models[dataset_name].predict(x[:, :expected_features])
                    else:
                        return self.models[dataset_name].predict(x)
                
                # Create a small explainer with a subset of background samples
                explainer = shap.KernelExplainer(model_predict, np.zeros((1, expected_features)))
                
                # Prepare input for SHAP based on expected features
                if X.shape[1] != expected_features:
                    if X.shape[1] < expected_features:
                        # Pad with zeros
                        padding = np.zeros((X.shape[0], expected_features - X.shape[1]))
                        X_for_shap = np.hstack((X, padding))
                    else:
                        # Select first features
                        X_for_shap = X[:, :expected_features]
                else:
                    X_for_shap = X
                    
                # Get SHAP values
                shap_values = explainer.shap_values(X_for_shap)
                
                # Create feature importance dictionary
                if isinstance(shap_values, list):
                    # For multi-class models, use the values for the predicted class
                    pred_class = np.argmax(model_predict(X_for_shap)[0])
                    importance = np.abs(shap_values[pred_class][0])
                else:
                    importance = np.abs(shap_values[0])
                    
                # Normalize importance to 0-1
                if np.max(importance) > 0:
                    importance = importance / np.max(importance)
                    
                # Create feature dictionary
                feat_importance = {}
                for i, (feat, imp) in enumerate(zip(feature_names, importance)):
                    if i < actual_features:  # Only include original features
                        feat_importance[feat] = float(imp)
                        
                # Sort by importance
                feat_importance = {k: v for k, v in sorted(
                    feat_importance.items(), 
                    key=lambda item: item[1], 
                    reverse=True
                )}
                
                return feat_importance
                
            except Exception as e:
                print(f"Error explaining prediction with SHAP: {str(e)}")
                # Fallback to model weights for importance
                # This is a more accurate fallback than random values
                try:
                    # Get the model weights from the first layer
                    weights = self.models[dataset_name].layers[1].get_weights()[0]
                    
                    # Get absolute weights and sum them across outputs
                    importance = np.sum(np.abs(weights), axis=1)
                    
                    # Normalize to 0-1
                    if np.max(importance) > 0:
                        importance = importance / np.max(importance)
                    
                    # Create feature importance dictionary
                    feat_importance = {}
                    for i, imp in enumerate(importance):
                        if i < min(actual_features, len(feature_names)):
                            feat_importance[feature_names[i]] = float(imp)
                    
                    # Sort by importance
                    feat_importance = {k: v for k, v in sorted(
                        feat_importance.items(), 
                        key=lambda item: item[1], 
                        reverse=True
                    )}
                    
                    return feat_importance
                
                except Exception as e2:
                    print(f"Error getting weights for importance: {str(e2)}")
                    # If all else fails, return empty dictionary
                    # No random values - we want real explanations or nothing
                    return {}
                
        except Exception as e:
            print(f"Error in explain_prediction: {str(e)}")
            return {}
    
    def predict_anomalies(self, X, dataset_name, feature_names=None):
        """
        Predict anomalies for a specific dataset
        
        Args:
            X: Input features
            dataset_name: Name of the dataset
            feature_names: Feature names
            
        Returns:
            Dictionary with prediction results
        """
        if dataset_name not in self.models or dataset_name not in self.scalers:
            return {
                "error": f"Model or scaler for {dataset_name} not loaded"
            }
            
        try:
            # Get expected feature count for this model
            expected_features = self.dataset_stats[dataset_name]['n_features']
            actual_features = X.shape[1]
            
            print(f"Model {dataset_name} expects {expected_features} features, got {actual_features}")
            
            # Prepare the input by padding or selecting features
            if actual_features < expected_features:
                # Pad with zeros if we don't have enough features
                padding = np.zeros((X.shape[0], expected_features - actual_features))
                X_padded = np.hstack((X, padding))
                print(f"Padded input from {actual_features} to {expected_features} features")
                X_for_model = X_padded
            elif actual_features > expected_features:
                # Select only the first expected_features if we have too many
                X_selected = X[:, :expected_features]
                print(f"Selected first {expected_features} features from {actual_features}")
                X_for_model = X_selected
            else:
                X_for_model = X
            
            # Scale the input
            X_scaled = self.scalers[dataset_name].transform(X_for_model)
            
            # Get model prediction
            y_pred_proba = self.models[dataset_name].predict(X_scaled)
            y_pred = np.argmax(y_pred_proba, axis=1)
            
            # Get isolation forest prediction if available
            if dataset_name in self.iso_forests:
                iso_pred = self.iso_forests[dataset_name].predict(X_scaled)
                # Convert to our threat types: -1 is anomaly, 1 is normal
                iso_pred = np.where(iso_pred == -1, 1, 0)  # 1 is Anomaly, 0 is Normal
            else:
                iso_pred = np.zeros_like(y_pred)
                
            # Create LOF model for online prediction
            lof = LocalOutlierFactor(n_neighbors=min(20, X_scaled.shape[0] // 2 if X_scaled.shape[0] > 4 else 2), 
                                    contamination=0.2, novelty=True)
            lof.fit(X_scaled)
            lof_pred = lof.predict(X_scaled)
            # Convert to our threat types: -1 is anomaly, 1 is normal
            lof_pred = np.where(lof_pred == -1, 1, 0)  # 1 is Anomaly, 0 is Normal
            
            # Combine predictions
            # If isolation forest or LOF detects an anomaly but model predicts normal,
            # it could be a zero-day attack (unseen in training)
            combined_pred = np.zeros_like(y_pred)
            confidence = np.zeros_like(y_pred, dtype=float)
            explanations = []
            
            # Use model-based threshold to determine zero-day threats
            zero_day_threshold = 0.6  # Confidence threshold for model
            
            for i in range(len(y_pred)):
                # Calculate confidence
                max_proba = np.max(y_pred_proba[i])
                
                # Zero-day detection based on model and anomaly detector disagreement
                # Both anomaly detectors agree it's an anomaly, but model disagrees with high confidence
                if (iso_pred[i] == 1 and lof_pred[i] == 1 and y_pred[i] == 0) or \
                   (max_proba < zero_day_threshold and (iso_pred[i] == 1 or lof_pred[i] == 1)):
                    # This could be a zero-day attack
                    combined_pred[i] = 2  # Zero-Day
                    confidence[i] = max((1.0 - max_proba), 0.5)  # Higher confidence for lower model certainty
                # If model predicts an attack class or one detector finds an anomaly
                elif y_pred[i] > 0 or iso_pred[i] == 1 or lof_pred[i] == 1:
                    combined_pred[i] = 1  # Known Anomaly
                    confidence[i] = max(max_proba, 0.5)  # Ensure reasonable confidence
                # Normal traffic
                else:
                    combined_pred[i] = 0  # Normal
                    confidence[i] = max_proba
                    
                # Get feature importance explanation
                if combined_pred[i] > 0:  # Only explain anomalies
                    explanation = self.explain_prediction(
                        X_scaled[i:i+1], 
                        dataset_name,
                        feature_names
                    )
                    explanations.append(explanation)
                else:
                    explanations.append(None)
                    
            # Create result dictionary
            results = {
                "count": len(y_pred),
                "model_predictions": y_pred.tolist(),
                "isolation_forest_predictions": iso_pred.tolist(),
                "lof_predictions": lof_pred.tolist(),
                "combined_predictions": combined_pred.tolist(),
                "confidence": confidence.tolist(),
                "probabilities": y_pred_proba.tolist(),
                "threat_types": [THREAT_TYPES[p] for p in combined_pred],
                "explanations": explanations
            }
            
            return results
        except Exception as e:
            print(f"Error predicting anomalies: {str(e)}")
            traceback.print_exc()  # Print the full stack trace
            return {"error": f"Failed to predict anomalies: {str(e)}"}
    
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
            elif isinstance(test_data, pd.DataFrame):
                print(f"Using provided DataFrame with shape {test_data.shape}")
                df = test_data.head(max_samples)
            else:
                return {"error": "Test data must be a file path or DataFrame"}
                
            print(f"Loaded test data with shape: {df.shape}")
            
            # Assume the last column is the label
            X = df.iloc[:, :-1]
            
            # Handle the label - it could be a string or already numeric
            y_true_col = df.iloc[:, -1]
            try:
                y_true = y_true_col.astype(int)
            except (ValueError, TypeError):
                # If conversion fails, it's likely a string label like 'attack' or 'normal'
                # Just keep the original for reference, we don't use it for prediction anyway
                y_true = y_true_col
                print(f"Note: Labels are non-numeric: {y_true.unique()[:5]}")
            
            feature_names = list(X.columns)
            
            print(f"Test data has {X.shape[1]} features")
            
            # If no dataset specified, try all available datasets
            if dataset_name is None or dataset_name not in self.dataset_stats:
                # Try all datasets
                all_results = {}
                for name in self.dataset_stats.keys():
                    print(f"Using model for {name}")
                    # Select the appropriate features for this dataset
                    n_features = self.dataset_stats[name]['n_features']
                    
                    # Use only the first n_features if we have too many
                    if X.shape[1] > n_features:
                        print(f"Dataset {name} has {n_features} features, selecting first {n_features} features")
                        X_subset = X.iloc[:, :n_features]
                        feature_subset = feature_names[:n_features]
                    else:
                        # Pad with zeros if we have too few
                        if X.shape[1] < n_features:
                            print(f"Dataset {name} has {n_features} features, padding with zeros")
                            padding = pd.DataFrame(
                                np.zeros((X.shape[0], n_features - X.shape[1])),
                                columns=[f"padding_{i}" for i in range(n_features - X.shape[1])]
                            )
                            X_subset = pd.concat([X, padding], axis=1)
                            feature_subset = feature_names + [f"padding_{i}" for i in range(n_features - X.shape[1])]
                        else:
                            X_subset = X
                            feature_subset = feature_names
                    
                    # Predict with this model
                    all_results[name] = self.predict_anomalies(X_subset, name, feature_subset)
                    
                # Combine results from all models
                ensemble_results = self._combine_results(all_results)
                
                # Filter out normal predictions if requested
                ensemble_results = {
                    k: v for k, v in ensemble_results.items() 
                    if k != "threat_types" or v != "Normal"
                }
                
                # Process the results into a final report
                return self._create_report(
                    ensemble_results,
                    df,
                    feature_names,
                    'ensemble',
                    start_time
                )
            else:
                # Use the specified dataset
                n_features = self.dataset_stats[dataset_name]['n_features']
                
                # Use only the first n_features if we have too many
                if X.shape[1] > n_features:
                    print(f"Dataset {dataset_name} has {n_features} features, selecting first {n_features} features")
                    X_subset = X.iloc[:, :n_features]
                    feature_subset = feature_names[:n_features]
                else:
                    # Pad with zeros if we have too few
                    if X.shape[1] < n_features:
                        print(f"Dataset {dataset_name} has {n_features} features, padding with zeros")
                        padding = pd.DataFrame(
                            np.zeros((X.shape[0], n_features - X.shape[1])),
                            columns=[f"padding_{i}" for i in range(n_features - X.shape[1])]
                        )
                        X_subset = pd.concat([X, padding], axis=1)
                        feature_subset = feature_names + [f"padding_{i}" for i in range(n_features - X.shape[1])]
                    else:
                        X_subset = X
                        feature_subset = feature_names
                
                # Predict with this model
                results = self.predict_anomalies(X_subset, dataset_name, feature_subset)
                
                # Process the results into a final report
                return self._create_report(
                    results, 
                    df,
                    feature_names,
                    dataset_name,
                    start_time
                )
                
        except Exception as e:
            print(f"Error detecting threats: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": f"Failed to detect threats: {str(e)}"}
            
    def _combine_results(self, all_results):
        """
        Combine results from multiple models using majority voting
        
        Args:
            all_results: Dictionary with results from each model
            
        Returns:
            Combined results
        """
        # Check if we have any valid results
        valid_results = {k: v for k, v in all_results.items() if "error" not in v}
        if not valid_results:
            return {"error": "No valid results from any model"}
            
        # Get the number of records (should be the same for all)
        n_records = list(valid_results.values())[0]["count"]
        
        # Initialize arrays for the ensemble
        ensemble_pred = np.zeros(n_records)
        ensemble_conf = np.zeros(n_records)
        
        # For each record, get predictions from all models
        for i in range(n_records):
            votes = {}
            confidences = {}
            
            for model_name, result in valid_results.items():
                pred = result["combined_predictions"][i]
                conf = result["confidence"][i]
                
                votes[pred] = votes.get(pred, 0) + 1
                confidences[pred] = confidences.get(pred, 0) + conf
                
            # Get the majority vote
            max_votes = 0
            max_pred = 0
            
            for pred, vote_count in votes.items():
                if vote_count > max_votes:
                    max_votes = vote_count
                    max_pred = pred
                # If there's a tie, prefer more severe threats
                elif vote_count == max_votes and pred > max_pred:
                    max_pred = pred
                    
            # Get the average confidence for this prediction
            avg_conf = confidences[max_pred] / votes[max_pred]
            
            ensemble_pred[i] = max_pred
            ensemble_conf[i] = avg_conf
            
        # Create the ensemble result
        ensemble_result = {
            "count": n_records,
            "combined_predictions": ensemble_pred.tolist(),
            "confidence": ensemble_conf.tolist(),
            "threat_types": [THREAT_TYPES[int(p)] for p in ensemble_pred],
            "explanations": []
        }
        
        # Add explanations
        for i in range(n_records):
            # Get the model with highest confidence for this prediction
            best_model = None
            best_conf = 0
            
            for model_name, result in valid_results.items():
                if result["combined_predictions"][i] == ensemble_pred[i]:
                    if result["confidence"][i] > best_conf:
                        best_conf = result["confidence"][i]
                        best_model = model_name
                        
            # Use the explanation from the best model
            if best_model and ensemble_pred[i] > 0:  # Only for anomalies
                ensemble_result["explanations"].append(
                    valid_results[best_model]["explanations"][i]
                )
            else:
                ensemble_result["explanations"].append(None)
                
        return ensemble_result
    
    def _create_report(self, results, df, feature_names, dataset_name, start_time):
        """
        Create a report from detection results
        
        Args:
            results: Detection results
            df: Original dataframe
            feature_names: Feature names
            dataset_name: Name of the dataset
            start_time: Start time of detection
            
        Returns:
            Report dictionary
        """
        try:
            if "error" in results:
                return results
                
            # Get counts
            threat_types = results["threat_types"]
            threat_counts = {
                "Normal": 0,
                "Anomaly": 0,
                "Zero-Day": 0
            }
            
            for t_type in threat_types:
                if t_type in threat_counts:
                    threat_counts[t_type] += 1
                    
            # Calculate percentages
            total = sum(threat_counts.values())
            threat_percentages = {
                k: round((v / total) * 100, 2) if total > 0 else 0 
                for k, v in threat_counts.items()
            }
            
            # Determine risk level
            risk_level = "LOW RISK - No Threats Detected"
            if threat_counts["Zero-Day"] > 0:
                risk_level = "CRITICAL RISK - Multiple Zero-Day Threats Detected"
            elif threat_counts["Anomaly"] > 5:
                risk_level = "HIGH RISK - Multiple Anomalies Detected"
            elif threat_counts["Anomaly"] > 0:
                risk_level = "MEDIUM RISK - Multiple Anomalies Detected"
                
            # Create detailed threats list
            detailed_threats = []
            for i in range(len(threat_types)):
                if threat_types[i] != "Normal":
                    severity = "HIGH" if threat_types[i] == "Zero-Day" else "MEDIUM"
                    
                    # Get record details
                    record = df.iloc[i].to_dict()
                    
                    # Convert NumPy types to native Python types
                    record = convert_to_serializable(record)
                    
                    # Get feature importance
                    features = results["explanations"][i] if i < len(results["explanations"]) else {}
                    
                    # Convert feature importance to native Python types
                    features = convert_to_serializable(features)
                    
                    # Add threat details
                    detailed_threats.append({
                        "id": i,
                        "type": threat_types[i],
                        "confidence": round(float(results["confidence"][i]) * 100, 2),
                        "severity": severity,
                        "features": features,
                        "record": record
                    })
            
            # Create final report
            report = {
                "dataset": dataset_name,
                "total_records": len(df),
                "analysis_time": round(time.time() - start_time, 2),
                "threat_distribution": {
                    "counts": threat_counts,
                    "percentages": threat_percentages
                },
                "risk_assessment": risk_level,
                "detailed_threats": detailed_threats
            }
            
            # Convert any remaining numpy types to native Python types
            report = convert_to_serializable(report)
            
            # Save to file for debugging
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = f"analysis_{timestamp}.json"
            try:
                with open(output_file, "w") as f:
                    json.dump(report, f, indent=2)
                print(f"Saved analysis results to {output_file}")
            except Exception as e:
                print(f"Error saving results: {str(e)}")
            
            return report
            
        except Exception as e:
            print(f"Error creating report: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"error": f"Failed to create report: {str(e)}"}
    
    def save_results(self, results, output_dir="results"):
        """
        Save detection results to a file
        
        Args:
            results: Detection results
            output_dir: Directory to save results
            
        Returns:
            Path to the saved file
        """
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"unified_detection_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        # Save the results
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
                
            print(f"Results saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"Error saving results: {str(e)}")
            return None
        
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Detect anomalies with the unified VARMAX model')
    parser.add_argument('--model_dir', type=str, default='unified_model',
                        help='Directory with trained models')
    parser.add_argument('--test_data', type=str, required=True,
                        help='Path to test data CSV file')
    parser.add_argument('--dataset', type=str, default=None,
                        help='Dataset to use for detection (kdd, train, unsw, or None for ensemble)')
    parser.add_argument('--max_samples', type=int, default=100,
                        help='Maximum number of samples to analyze')
    parser.add_argument('--output_dir', type=str, default='results',
                        help='Directory to save results')
    args = parser.parse_args()
    
    # Create detector
    detector = UnifiedAnomalyDetector(model_dir=args.model_dir)
    
    # Detect threats
    results = detector.detect_threats(
        test_data=args.test_data,
        dataset_name=args.dataset,
        max_samples=args.max_samples
    )
    
    # Save results
    if "error" not in results:
        detector.save_results(results, output_dir=args.output_dir)
        
        # Print summary
        print("\nDetection Summary:")
        print("-----------------")
        print(f"Total records analyzed: {results['total_records']}")
        print(f"Analysis time: {results['analysis_time']} seconds")
        print(f"Risk assessment: {results['risk_assessment']}")
        print("\nThreat Distribution:")
        
        for threat_type, percentage in results["threat_distribution"]["percentages"].items():
            print(f"  {threat_type}: {percentage}%")
            
        print("\nDetailed Threats:")
        for threat in results.get("detailed_threats", []):
            print(f"  ID: {threat['id']} | Type: {threat['type']} | Confidence: {threat['confidence']}% | Severity: {threat['severity']}")
            if threat["features"]:
                print("    Top contributing features:")
                for feature, importance in list(threat["features"].items())[:3]:
                    print(f"      {feature}: {importance:.4f}")
    else:
        print(f"Error: {results['error']}")
    
if __name__ == "__main__":
    main() 