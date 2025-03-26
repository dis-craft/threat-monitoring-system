import os
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from tensorflow.keras.models import load_model
import argparse
from datetime import datetime
import json

class KerasVARMAXPredictor:
    def __init__(self, model_dir='keras_models'):
        """
        Unified predictor for VARMAX models
        
        Args:
            model_dir: Directory containing models
        """
        self.model_dir = model_dir
        self.unified_dir = os.path.join(model_dir, 'unified')
        self.models = {}
        self.preprocessors = {}
        self.dataset_stats = None
        
        # Load models if unified directory exists
        if os.path.exists(self.unified_dir):
            self.load_from_unified()
        else:
            self.load_individual_models()
    
    def load_from_unified(self):
        """Load models from unified directory"""
        print(f"Loading models from {self.unified_dir}")
        
        # Load dataset stats
        stats_path = os.path.join(self.unified_dir, "dataset_stats.joblib")
        if os.path.exists(stats_path):
            self.dataset_stats = joblib.load(stats_path)
            print(f"Loaded dataset stats for {len(self.dataset_stats)} datasets")
        else:
            print("Dataset stats file not found")
        
        # Load models and preprocessors
        for dataset_name in self.dataset_stats.keys():
            # Load model
            model_path = os.path.join(self.unified_dir, f"{dataset_name}_model.h5")
            if os.path.exists(model_path):
                self.models[dataset_name] = load_model(model_path)
                print(f"Loaded model for {dataset_name}")
            else:
                print(f"Model for {dataset_name} not found")
            
            # Load preprocessor
            preprocessor_path = os.path.join(self.unified_dir, f"{dataset_name}_scaler.joblib")
            if os.path.exists(preprocessor_path):
                self.preprocessors[dataset_name] = joblib.load(preprocessor_path)
                print(f"Loaded preprocessor for {dataset_name}")
            else:
                print(f"Preprocessor for {dataset_name} not found")
    
    def load_individual_models(self):
        """Load individual models from model directory"""
        print(f"Loading individual models from {self.model_dir}")
        
        # Try to find all model files
        for filename in os.listdir(self.model_dir):
            if filename.endswith("_model.h5"):
                dataset_name = filename.split("_model.h5")[0]
                
                # Load model
                model_path = os.path.join(self.model_dir, filename)
                self.models[dataset_name] = load_model(model_path)
                print(f"Loaded model for {dataset_name}")
                
                # Try to load corresponding preprocessor
                preprocessor_path = os.path.join(self.model_dir, f"{dataset_name}_scaler.joblib")
                if os.path.exists(preprocessor_path):
                    self.preprocessors[dataset_name] = joblib.load(preprocessor_path)
                    print(f"Loaded preprocessor for {dataset_name}")
    
    def predict(self, data, dataset_name=None):
        """
        Make predictions with the appropriate model
        
        Args:
            data: DataFrame with features
            dataset_name: Name of the dataset to use for prediction
                        If None, try all models and use ensemble
        
        Returns:
            Predictions and anomaly scores
        """
        if not self.models:
            raise ValueError("No models loaded. Train models first.")
        
        if dataset_name and dataset_name in self.models:
            # Use specified model
            return self._predict_with_model(data, dataset_name)
        else:
            # Try all models and ensemble results
            return self._ensemble_predict(data)
    
    def _predict_with_model(self, data, dataset_name):
        """Use a specific model for prediction"""
        model = self.models[dataset_name]
        preprocessor = self.preprocessors.get(dataset_name)
        
        # Preprocess data
        if preprocessor:
            data_scaled = preprocessor.transform(data)
        else:
            data_scaled = data.values
        
        # Get predictions
        predictions = model.predict(data_scaled)
        
        # Get predicted classes and probabilities
        pred_classes = np.argmax(predictions, axis=1)
        pred_probs = np.max(predictions, axis=1)
        
        # Calculate anomaly score based on entropy of predictions
        entropy = -np.sum(predictions * np.log2(np.clip(predictions, 1e-10, 1.0)), axis=1)
        max_entropy = np.log2(predictions.shape[1])  # Maximum possible entropy
        anomaly_scores = entropy / max_entropy  # Normalize to [0, 1]
        
        return {
            'predictions': pred_classes,
            'probabilities': pred_probs,
            'raw_predictions': predictions,
            'anomaly_scores': anomaly_scores
        }
    
    def _ensemble_predict(self, data):
        """Ensemble predictions from all models"""
        all_predictions = {}
        ensemble_anomaly_scores = np.zeros(len(data))
        
        for dataset_name in self.models.keys():
            try:
                result = self._predict_with_model(data, dataset_name)
                all_predictions[dataset_name] = result
                
                # Add anomaly scores to ensemble
                ensemble_anomaly_scores += result['anomaly_scores']
            except Exception as e:
                print(f"Error predicting with {dataset_name} model: {str(e)}")
        
        # Average anomaly scores
        if all_predictions:
            ensemble_anomaly_scores /= len(all_predictions)
        
        # Choose the model with the highest confidence for final predictions
        final_predictions = np.zeros(len(data), dtype=int)
        final_probabilities = np.zeros(len(data))
        
        for i in range(len(data)):
            best_prob = 0
            best_class = 0
            
            for dataset_name, result in all_predictions.items():
                prob = result['probabilities'][i]
                if prob > best_prob:
                    best_prob = prob
                    best_class = result['predictions'][i]
            
            final_predictions[i] = best_class
            final_probabilities[i] = best_prob
        
        return {
            'predictions': final_predictions,
            'probabilities': final_probabilities,
            'anomaly_scores': ensemble_anomaly_scores,
            'individual_results': all_predictions
        }
    
    def detect_threats(self, data, anomaly_threshold=0.5, confidence_threshold=0.8):
        """
        Detect threats in the data
        
        Args:
            data: DataFrame with features
            anomaly_threshold: Threshold for anomaly detection
            confidence_threshold: Threshold for high confidence predictions
        
        Returns:
            List of detected threats
        """
        # Get predictions
        results = self.predict(data)
        
        threats = []
        
        for i in range(len(data)):
            # Determine attack type based on prediction and anomaly score
            pred_class = results['predictions'][i]
            anomaly_score = results['anomaly_scores'][i]
            confidence = results['probabilities'][i]
            
            if anomaly_score > anomaly_threshold:
                if confidence > confidence_threshold:
                    attack_type = "Zero-Day Attack"
                else:
                    attack_type = "Anomaly"
            else:
                attack_type = "Normal"
            
            # Determine severity
            if attack_type == "Zero-Day Attack":
                severity = "Critical" if confidence > 0.9 else "High"
            elif attack_type == "Anomaly":
                severity = "High" if anomaly_score > 0.7 else "Medium"
            else:
                severity = "Low"
            
            # Create threat object
            threat = self._create_threat_object(
                data.iloc[i] if isinstance(data, pd.DataFrame) else data[i],
                attack_type,
                severity,
                confidence,
                anomaly_score,
                i
            )
            
            threats.append(threat)
        
        return threats
    
    def _create_threat_object(self, row_data, attack_type, severity, confidence, anomaly_score, idx):
        """Create a threat object with details"""
        timestamp = datetime.now().isoformat()
        
        # Generate unique ID based on timestamp and index
        threat_id = str(abs(hash(f"{timestamp}-{idx}")) % 100000)
        
        # Extract source IP if available, or generate random
        ip = str(getattr(row_data, 'ip', getattr(row_data, 'source_ip', 
                getattr(row_data, 'src_ip', f"192.168.1.{idx % 255}"))))
        
        # Get network details
        source_port = int(getattr(row_data, 'source_port', getattr(row_data, 'src_port', 0)))
        dest_port = int(getattr(row_data, 'dest_port', getattr(row_data, 'dst_port', 0)))
        protocol = str(getattr(row_data, 'protocol', 'Unknown'))
        
        # Get HTTP details if available
        method = str(getattr(row_data, 'method', getattr(row_data, 'http_method', 'GET')))
        url_path = str(getattr(row_data, 'url_path', getattr(row_data, 'path', '/')))
        
        # Create explanation based on attack type
        if attack_type == "Zero-Day Attack":
            explanation = f"Previously unseen attack pattern detected with confidence {confidence:.2f}. The anomaly score is {anomaly_score:.2f}."
        elif attack_type == "Anomaly":
            explanation = f"Network traffic deviates from baseline with anomaly score {anomaly_score:.2f}."
        else:
            explanation = f"Traffic matches normal expected patterns with confidence {confidence:.2f}. No suspicious indicators detected."
        
        # Create the threat object
        threat = {
            "id": threat_id,
            "timestamp": timestamp,
            "ip": ip,
            "attack_type": attack_type,
            "severity": severity,
            "status": "Active" if attack_type != "Normal" else "Resolved",
            "details": {
                "protocol": protocol,
                "method": method,
                "url_path": url_path,
                "source_port": source_port,
                "destination_port": dest_port,
                "user_agent": "Mozilla/5.0",
                "confidence_score": float(confidence),
                "anomaly_score": float(anomaly_score),
                "top_feature": "n/a",
                "prediction_explanation": explanation
            }
        }
        
        return threat
    
    def save_threats_to_json(self, threats, output_path="detected_threats.json"):
        """Save detected threats to a JSON file"""
        with open(output_path, 'w') as f:
            json.dump(threats, f, indent=2)
        
        print(f"Saved {len(threats)} threats to {output_path}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Make predictions with VARMAX models')
    parser.add_argument('--input', type=str, required=True,
                      help='Path to input data CSV file')
    parser.add_argument('--model_dir', type=str, default='keras_models',
                      help='Directory containing models')
    parser.add_argument('--output', type=str, default='detected_threats.json',
                      help='Path to output JSON file')
    parser.add_argument('--anomaly_threshold', type=float, default=0.5,
                      help='Threshold for anomaly detection')
    parser.add_argument('--confidence_threshold', type=float, default=0.8,
                      help='Threshold for high confidence predictions')
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading data from {args.input}")
    try:
        data = pd.read_csv(args.input)
        print(f"Data loaded successfully. Shape: {data.shape}")
    except Exception as e:
        print(f"Error loading data: {str(e)}")
        return
    
    # Initialize predictor
    predictor = KerasVARMAXPredictor(model_dir=args.model_dir)
    
    # Detect threats
    print("\nDetecting threats...")
    threats = predictor.detect_threats(
        data, 
        anomaly_threshold=args.anomaly_threshold,
        confidence_threshold=args.confidence_threshold
    )
    
    # Save threats to JSON
    predictor.save_threats_to_json(threats, output_path=args.output)
    
    # Print summary
    attack_types = {}
    for threat in threats:
        attack_type = threat['attack_type']
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    print("\nThreat Detection Summary:")
    for attack_type, count in attack_types.items():
        print(f"  {attack_type}: {count}")
    
    print("\nPrediction completed successfully!")

if __name__ == "__main__":
    main() 