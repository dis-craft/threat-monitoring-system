import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import json
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama
init()

# Constants
MODEL_DIR = 'keras_models/unified'
TEST_DATA_PATH = 'C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\preprocessed_test_data.csv'
MAX_SAMPLES = 10  # Increased to 10 samples

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

def detect_anomalies():
    print(format_color("\n=== VARMAX THREAT DETECTION SYSTEM ===", Fore.CYAN + Style.BRIGHT))
    print(format_color(f"Analyzing first {MAX_SAMPLES} records from:", Fore.CYAN))
    print(f"  {TEST_DATA_PATH}\n")
    
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
        df = pd.read_csv(TEST_DATA_PATH)
        print(format_color(f"Loaded test data with shape: {df.shape}", Fore.GREEN))
        
        # Get the first MAX_SAMPLES rows
        df = df.head(MAX_SAMPLES)
        
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
                    }
                }
                
                record_threats.append(threat)
                
                # Display threat information
                print(f"  {dataset_name.upper()} model: {format_color(attack_type, color)} (Confidence: {severity*100:.2f}%)")
                print(f"    - Normal: {pred_probs[0]*100:.2f}%, Anomaly: {pred_probs[1]*100:.2f}%, Zero-Day: {pred_probs[2]*100:.2f}%")
        
        # Estimate feature importance for this record
        if record_anomalies > 0 or record_zero_days > 0:
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
        
        # Store threats for this record
        max_severity = max(threat['severity'] for threat in record_threats)
        verdict = [t for t in record_threats if t['severity'] == max_severity][0]
        
        # Determine the consensus verdict
        verdict_color = Fore.GREEN if verdict['attack_type'] == 'Normal' else Fore.RED if verdict['attack_type'] == 'Zero-Day' else Fore.YELLOW
        print(f"\n  {format_color('VERDICT:', verdict_color + Style.BRIGHT)} {format_color(verdict['attack_type'], verdict_color)} (Confidence: {verdict['confidence']:.2f}%)")
        
        # Add verdict info to threats
        for threat in record_threats:
            threat['is_consensus_verdict'] = (threat['severity'] == max_severity)
        
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
    
    # Overall verdict
    if total_zero_days > 0:
        overall_verdict = "High Risk - Zero-Day Threats Detected"
        verdict_color = Fore.RED
    elif total_anomalies > 0:
        overall_verdict = "Medium Risk - Anomalies Detected"
        verdict_color = Fore.YELLOW
    else:
        overall_verdict = "Low Risk - No Threats Detected"
        verdict_color = Fore.GREEN
    
    print(format_color("\nOVERALL ASSESSMENT:", Fore.CYAN + Style.BRIGHT))
    print(format_color(f"  {overall_verdict}", verdict_color + Style.BRIGHT))
    
    # Save detailed report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"detailed_analysis_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump({
            'analysis_timestamp': timestamp,
            'data_source': TEST_DATA_PATH,
            'records_analyzed': len(df),
            'models_used': list(models.keys()),
            'threat_distribution': attack_types,
            'overall_verdict': overall_verdict,
            'detailed_threats': all_threats
        }, f, indent=2)
    
    print(format_color(f"\nDetailed analysis saved to: {filename}", Fore.CYAN))

if __name__ == "__main__":
    detect_anomalies() 