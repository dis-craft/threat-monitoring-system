import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import json
from colorama import init, Fore, Style
from datetime import datetime
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# Initialize colorama
init()

# Constants
MODEL_DIR = 'keras_models/unified'
TEST_DATA_PATHS = [
    'C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\preprocessed_test_data.csv',
    'C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\KDD_Test_preprocessed.csv',
    'C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\UNSW_NB15_test_preprocessed.csv'
]
ANALYZED_DATASET = TEST_DATA_PATHS[0]  # Default to first dataset
MAX_SAMPLES = 100

# Anomaly threshold - higher means more sensitive detection
ANOMALY_THRESHOLD = 0.45
ZERODAY_THRESHOLD = 0.50

class SimpleModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(SimpleModel, self).__init__()
        self.model = nn.Sequential(
            nn.BatchNorm1d(input_size),
            nn.Linear(input_size, hidden_size * 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.BatchNorm1d(hidden_size * 2),
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.BatchNorm1d(hidden_size),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.BatchNorm1d(hidden_size // 2),
            nn.Linear(hidden_size // 2, output_size)
        )
    
    def forward(self, x):
        return self.model(x)

def format_color(text, color):
    return f"{color}{text}{Style.RESET_ALL}"

def estimate_feature_importance(sample, scalers, models, feature_names):
    """Estimate feature importance via perturbation analysis"""
    importances = {model_name: {} for model_name in models.keys()}
    
    for model_name, model in models.items():
        # Get baseline prediction
        scaled_data = scalers[model_name].transform(sample)
        with torch.no_grad():
            inputs = torch.FloatTensor(scaled_data)
            outputs = model(inputs)
            baseline_preds = torch.softmax(outputs, dim=1).numpy()[0]
            baseline_class = np.argmax(baseline_preds)
        
        # Perturb each feature and observe the effect
        for i, feature in enumerate(feature_names):
            perturbed = sample.copy()
            perturbed[0, i] = 0  # Set feature to 0 (neutral value)
            
            # Get new prediction
            scaled_perturbed = scalers[model_name].transform(perturbed)
            with torch.no_grad():
                inputs = torch.FloatTensor(scaled_perturbed)
                outputs = model(inputs)
                perturbed_preds = torch.softmax(outputs, dim=1).numpy()[0]
            
            # Calculate impact (how much prediction probability changed)
            impact = baseline_preds[baseline_class] - perturbed_preds[baseline_class]
            importances[model_name][feature] = impact
    
    return importances

def train_anomaly_detectors(X_train):
    """Train anomaly detection models to complement the deep learning models"""
    anomaly_detectors = {}
    
    # Isolation Forest
    print(format_color("Training Isolation Forest model...", Fore.CYAN))
    iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso_forest.fit(X_train)
    anomaly_detectors['isolation_forest'] = iso_forest
    
    # Local Outlier Factor
    print(format_color("Training Local Outlier Factor model...", Fore.CYAN))
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.1, novelty=True)
    lof.fit(X_train)
    anomaly_detectors['lof'] = lof
    
    return anomaly_detectors

def detect_anomalies(dataset_path=None, max_samples=None):
    if dataset_path:
        global ANALYZED_DATASET
        ANALYZED_DATASET = dataset_path
    
    if max_samples:
        global MAX_SAMPLES
        MAX_SAMPLES = max_samples
    
    print(format_color("\n=== ADVANCED VARMAX THREAT DETECTION SYSTEM ===", Fore.CYAN + Style.BRIGHT))
    print(format_color(f"Analyzing dataset:", Fore.CYAN))
    print(f"  {ANALYZED_DATASET}")
    print(format_color(f"Using the first {MAX_SAMPLES} records for analysis", Fore.CYAN))
    
    # Load dataset stats and models
    try:
        dataset_stats = joblib.load(os.path.join(MODEL_DIR, 'dataset_stats.joblib'))
        print(format_color("Successfully loaded dataset statistics", Fore.GREEN))
    except Exception as e:
        print(format_color(f"Error loading dataset stats: {str(e)}", Fore.RED))
        return
    
    # Load models and scalers
    models = {}
    scalers = {}
    
    for dataset_name in dataset_stats.keys():
        try:
            # Load model
            model = SimpleModel(
                input_size=dataset_stats[dataset_name]['n_features'],
                hidden_size=128,
                output_size=dataset_stats[dataset_name]['n_classes']
            )
            model.load_state_dict(torch.load(os.path.join(MODEL_DIR, f'{dataset_name}_model.pt')))
            model.eval()  # Set to evaluation mode
            models[dataset_name] = model
            
            # Load scaler
            scalers[dataset_name] = joblib.load(os.path.join(MODEL_DIR, f'{dataset_name}_scaler.joblib'))
            
            print(format_color(f"Successfully loaded model and scaler for: {dataset_name}", Fore.GREEN))
        except Exception as e:
            print(format_color(f"Error loading model {dataset_name}: {str(e)}", Fore.RED))
    
    # Load and preprocess test data
    try:
        df = pd.read_csv(ANALYZED_DATASET)
        print(format_color(f"Loaded test data with shape: {df.shape}", Fore.GREEN))
        
        # Get samples
        if MAX_SAMPLES and MAX_SAMPLES < len(df):
            df = df.head(MAX_SAMPLES)
            print(format_color(f"Using first {MAX_SAMPLES} samples for analysis", Fore.YELLOW))
        
        # If we have more than 20 features, select only the first 20
        feature_names = df.columns.tolist()[:20]
        if df.shape[1] > 20:
            print(format_color(f"Dataset has {df.shape[1]} features, selecting first 20 features:", Fore.YELLOW))
            print(f"  {', '.join(feature_names[:5])}... and {len(feature_names)-5} more")
            original_df = df.copy()  # Keep a copy of the original data
            df = df.iloc[:, :20]
        elif df.shape[1] < 20:
            print(format_color(f"Error: Expected at least 20 features, got {df.shape[1]}", Fore.RED))
            return
    except Exception as e:
        print(format_color(f"Error loading test data: {str(e)}", Fore.RED))
        return
    
    # Train anomaly detection models on the first 500 samples (or max available)
    X_train = df.head(min(500, len(df))).values
    anomaly_detectors = train_anomaly_detectors(X_train)
    
    # Process data and detect threats
    print(format_color("\n=== ANALYZING RECORDS ===", Fore.CYAN + Style.BRIGHT))
    
    all_threats = []
    total_anomalies = 0
    total_zero_days = 0
    
    for i, row in df.iterrows():
        # Prepare the data
        sample = row.values.reshape(1, -1)
        
        print(format_color(f"\nRecord #{i+1}:", Fore.CYAN + Style.BRIGHT))
        
        # Process with each model
        record_threats = []
        record_anomalies = 0
        record_zero_days = 0
        ensemble_votes = []
        
        # Run traditional anomaly detection models
        anomaly_scores = {}
        for detector_name, detector in anomaly_detectors.items():
            try:
                if detector_name == 'isolation_forest':
                    # Isolation Forest: negative score = anomaly
                    score = detector.decision_function(sample)[0]
                    is_anomaly = score < 0
                    norm_score = 1 - (score + 0.5) if score < 0 else 0
                elif detector_name == 'lof':
                    # LOF: negative score = anomaly
                    score = detector.decision_function(sample)[0]
                    is_anomaly = score < 0
                    norm_score = 1 - (score + 0.5) if score < 0 else 0
                
                anomaly_scores[detector_name] = {
                    'raw_score': score,
                    'normalized_score': norm_score,
                    'is_anomaly': is_anomaly
                }
                
                if is_anomaly:
                    if norm_score > ZERODAY_THRESHOLD:
                        ensemble_votes.append('Zero-Day')
                    else:
                        ensemble_votes.append('Anomaly')
                else:
                    ensemble_votes.append('Normal')
                
                print(f"  {detector_name.upper()}: {'Anomaly' if is_anomaly else 'Normal'} (Score: {norm_score:.4f})")
            except Exception as e:
                print(format_color(f"  Error with {detector_name}: {str(e)}", Fore.RED))
        
        # Process with deep learning models
        for dataset_name, model in models.items():
            # Scale the data
            try:
                scaled_data = scalers[dataset_name].transform(sample)
            except Exception as e:
                print(format_color(f"  Error scaling with {dataset_name} model: {str(e)}", Fore.RED))
                continue
            
            # Get predictions
            with torch.no_grad():
                inputs = torch.FloatTensor(scaled_data)
                outputs = model(inputs)
                predictions = torch.softmax(outputs, dim=1)
                predicted_class = torch.argmax(predictions, dim=1).item()
                
                # Convert predictions to numpy for easier handling
                pred_probs = predictions.numpy()[0]
                
                # Determine attack type and severity
                attack_type = 'Zero-Day' if predicted_class == 2 else 'Anomaly' if predicted_class == 1 else 'Normal'
                severity = float(max(pred_probs))
                
                # Add vote to ensemble
                ensemble_votes.append(attack_type)
                
                # Count anomalies and zero-days
                if attack_type == 'Anomaly':
                    record_anomalies += 1
                    total_anomalies += 1
                elif attack_type == 'Zero-Day':
                    record_zero_days += 1
                    total_zero_days += 1
                
                # Color code based on attack type
                color = Fore.GREEN if attack_type == 'Normal' else Fore.RED if attack_type == 'Zero-Day' else Fore.YELLOW
                
                # Create threat info
                threat = {
                    'record_id': i,
                    'model': dataset_name,
                    'attack_type': attack_type,
                    'severity': severity,
                    'confidence': severity * 100,
                    'prediction_probabilities': {
                        'normal': float(pred_probs[0]),
                        'anomaly': float(pred_probs[1]),
                        'zero_day': float(pred_probs[2])
                    },
                    'anomaly_scores': anomaly_scores
                }
                
                record_threats.append(threat)
                
                # Display threat information
                print(f"  {dataset_name.upper()} model: {format_color(attack_type, color)} (Confidence: {severity*100:.2f}%)")
                print(f"    - Normal: {pred_probs[0]*100:.2f}%, Anomaly: {pred_probs[1]*100:.2f}%, Zero-Day: {pred_probs[2]*100:.2f}%")
        
        # Perform ensemble voting (majority vote)
        ensemble_result = Counter(ensemble_votes).most_common(1)[0][0]
        ensemble_confidence = Counter(ensemble_votes)[ensemble_result] / len(ensemble_votes) * 100
        
        ensemble_color = Fore.GREEN
        if ensemble_result == 'Zero-Day':
            ensemble_color = Fore.RED
        elif ensemble_result == 'Anomaly':
            ensemble_color = Fore.YELLOW
        
        print(format_color(f"\n  ENSEMBLE PREDICTION: {format_color(ensemble_result, ensemble_color)} (Confidence: {ensemble_confidence:.2f}%)", Fore.MAGENTA + Style.BRIGHT))
        
        # Add ensemble prediction to threats
        ensemble_threat = {
            'record_id': i,
            'model': 'ensemble',
            'attack_type': ensemble_result,
            'severity': ensemble_confidence / 100,
            'confidence': ensemble_confidence,
            'is_ensemble': True,
            'votes': dict(Counter(ensemble_votes))
        }
        record_threats.append(ensemble_threat)
        
        # Estimate feature importance for this record if it's an anomaly or zero-day
        if ensemble_result != 'Normal':
            print(format_color("\n  Feature Importance Analysis:", Fore.MAGENTA))
            importances = estimate_feature_importance(sample, scalers, models, feature_names)
            
            # Get top features across models
            all_importances = {}
            for model_name, model_importances in importances.items():
                for feature, importance in model_importances.items():
                    if feature not in all_importances:
                        all_importances[feature] = 0
                    all_importances[feature] += abs(importance)
            
            # Show top 5 important features
            top_features = sorted(all_importances.items(), key=lambda x: x[1], reverse=True)[:5]
            for feature, importance in top_features:
                if importance > 0:
                    print(f"    - {feature}: {importance:.4f}")
            
            # Add top features to ensemble threat
            ensemble_threat['top_features'] = [
                {'name': feature, 'importance': importance} 
                for feature, importance in top_features if importance > 0
            ]
            
        # Add all threats for this record
        all_threats.extend(record_threats)
    
    # Calculate overall statistics
    total_threats = len(all_threats)
    attack_types = {}
    for threat in all_threats:
        attack_type = threat['attack_type']
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    # Print summary
    print(format_color("\n=== THREAT DETECTION SUMMARY ===", Fore.CYAN + Style.BRIGHT))
    print(f"Total records analyzed: {len(df)}")
    print(f"Total predictions (across all models): {total_threats}")
    print(f"Records with detected anomalies: {total_anomalies > 0}")
    print(f"Records with detected zero-day threats: {total_zero_days > 0}")
    
    print(format_color("\nThreat Distribution:", Fore.CYAN))
    for attack_type, count in attack_types.items():
        color = Fore.GREEN if attack_type == 'Normal' else Fore.RED if attack_type == 'Zero-Day' else Fore.YELLOW
        print(f"  {format_color(attack_type, color)}: {count} ({(count/total_threats)*100:.2f}%)")
    
    # Get ensemble predictions
    ensemble_predictions = [t for t in all_threats if t.get('is_ensemble', False)]
    ensemble_counts = {}
    for threat in ensemble_predictions:
        attack_type = threat['attack_type']
        ensemble_counts[attack_type] = ensemble_counts.get(attack_type, 0) + 1
    
    print(format_color("\nEnsemble Model Predictions:", Fore.CYAN))
    for attack_type, count in ensemble_counts.items():
        color = Fore.GREEN if attack_type == 'Normal' else Fore.RED if attack_type == 'Zero-Day' else Fore.YELLOW
        print(f"  {format_color(attack_type, color)}: {count} ({(count/len(ensemble_predictions))*100:.2f}%)")
    
    # Overall verdict based on ensemble
    zero_day_percentage = ensemble_counts.get('Zero-Day', 0) / len(ensemble_predictions) * 100
    anomaly_percentage = ensemble_counts.get('Anomaly', 0) / len(ensemble_predictions) * 100
    
    if zero_day_percentage > 15:
        overall_verdict = "CRITICAL RISK - Multiple Zero-Day Threats Detected"
        verdict_color = Fore.RED + Style.BRIGHT
    elif zero_day_percentage > 5:
        overall_verdict = "HIGH RISK - Zero-Day Threats Detected"
        verdict_color = Fore.RED
    elif anomaly_percentage > 15:
        overall_verdict = "MEDIUM RISK - Multiple Anomalies Detected"
        verdict_color = Fore.YELLOW + Style.BRIGHT
    elif anomaly_percentage > 5:
        overall_verdict = "ELEVATED RISK - Anomalies Detected"
        verdict_color = Fore.YELLOW
    else:
        overall_verdict = "LOW RISK - Minimal Threats Detected"
        verdict_color = Fore.GREEN
    
    print(format_color("\nOVERALL ASSESSMENT:", Fore.CYAN + Style.BRIGHT))
    print(format_color(f"  {overall_verdict}", verdict_color))
    
    # Save detailed report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"advanced_analysis_{timestamp}.json"
    
    # Filter out non-serializable objects (e.g., PyTorch models)
    serializable_threats = []
    for threat in all_threats:
        serializable_threat = {k: v for k, v in threat.items() if k != 'model_obj'}
        
        # Handle anomaly scores (scikit-learn objects are not JSON serializable)
        if 'anomaly_scores' in serializable_threat:
            scores_dict = {}
            for detector, scores in serializable_threat['anomaly_scores'].items():
                scores_dict[detector] = {
                    'raw_score': float(scores['raw_score']),
                    'normalized_score': float(scores['normalized_score']),
                    'is_anomaly': bool(scores['is_anomaly'])
                }
            serializable_threat['anomaly_scores'] = scores_dict
        
        # Convert numpy data types to Python native types
        for key, value in serializable_threat.items():
            if isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(v, 'dtype') and hasattr(v, 'tolist'):
                        value[k] = float(v)
            elif hasattr(value, 'dtype') and hasattr(value, 'tolist'):
                serializable_threat[key] = float(value)
        
        serializable_threats.append(serializable_threat)
    
    # Make sure all dictionary values are JSON serializable
    def convert_to_serializable(obj):
        if isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_serializable(item) for item in obj]
        elif hasattr(obj, 'dtype') and hasattr(obj, 'tolist'):
            return float(obj)
        elif isinstance(obj, (np.int64, np.int32, np.int16, np.int8)):
            return int(obj)
        elif isinstance(obj, (np.float64, np.float32, np.float16)):
            return float(obj)
        else:
            return obj
    
    report_data = {
        'analysis_timestamp': timestamp,
        'data_source': ANALYZED_DATASET,
        'records_analyzed': len(df),
        'models_used': list(models.keys()) + list(anomaly_detectors.keys()),
        'threat_distribution': {k: int(v) for k, v in attack_types.items()},
        'ensemble_distribution': {k: int(v) for k, v in ensemble_counts.items()},
        'overall_verdict': overall_verdict,
        'detailed_threats': convert_to_serializable(serializable_threats)
    }
    
    with open(filename, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(format_color(f"\nDetailed analysis saved to: {filename}", Fore.CYAN))
    
    # Return data for API usage
    return {
        'success': True,
        'threats': convert_to_serializable(serializable_threats),
        'stats': {
            'total_samples': int(len(df)),
            'detected_threats': int(len([t for t in serializable_threats if t.get('is_ensemble', False) and t['attack_type'] != 'Normal'])),
            'models_used': list(models.keys()) + list(anomaly_detectors.keys()),
            'threat_distribution': {k: int(v) for k, v in ensemble_counts.items()},
            'overall_verdict': overall_verdict
        }
    }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced VARMAX Threat Detection')
    parser.add_argument('--dataset', '-d', choices=[0, 1, 2], type=int, default=0,
                        help='Dataset index to analyze (0: preprocessed_test_data.csv, 1: KDD_Test_preprocessed.csv, 2: UNSW_NB15_test_preprocessed.csv)')
    parser.add_argument('--samples', '-s', type=int, default=100,
                        help='Number of samples to analyze')
    
    args = parser.parse_args()
    
    # Select dataset
    dataset_path = TEST_DATA_PATHS[args.dataset]
    
    detect_anomalies(dataset_path, args.samples) 