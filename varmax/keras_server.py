import os
import json
import logging
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from flask import Flask, request, jsonify, send_from_directory
from sklearn.preprocessing import StandardScaler
import joblib

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MODEL_DIR = 'keras_models/unified'
DEFAULT_TEST_PATH = 'C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\KDD_Test_preprocessed.csv'

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

class ThreatDetector:
    def __init__(self):
        self.dataset_stats = joblib.load(os.path.join(MODEL_DIR, 'dataset_stats.joblib'))
        self.models = {}
        self.scalers = {}
        
        # Load models and scalers for each dataset
        for dataset_name in self.dataset_stats.keys():
            logger.info(f"Loading model and scaler for {dataset_name}")
            
            # Load model
            model = SimpleModel(
                input_size=self.dataset_stats[dataset_name]['n_features'],
                hidden_size=128,
                output_size=self.dataset_stats[dataset_name]['n_classes']
            )
            model.load_state_dict(torch.load(os.path.join(MODEL_DIR, f'{dataset_name}_model.pt')))
            model.eval()  # Set to evaluation mode
            self.models[dataset_name] = model
            
            # Load scaler
            self.scalers[dataset_name] = joblib.load(os.path.join(MODEL_DIR, f'{dataset_name}_scaler.joblib'))
    
    def detect_threats(self, test_data_path, max_samples=100):
        logger.info(f"Loading test data from {test_data_path}")
        try:
            # Load and preprocess test data
            df = pd.read_csv(test_data_path)
            logger.info(f"Loaded test data with shape: {df.shape}")
            
            if max_samples:
                df = df.head(max_samples)
            
            # If we have more than 20 features, select only the first 20
            if df.shape[1] > 20:
                logger.info(f"Dataset has {df.shape[1]} features, selecting first 20 features")
                df = df.iloc[:, :20]
            elif df.shape[1] < 20:
                raise ValueError(f"Expected at least 20 features, got {df.shape[1]}")
            
            threats = []
            
            # Process data in batches
            batch_size = 32
            for i in range(0, len(df), batch_size):
                batch = df.iloc[i:i+batch_size]
                
                # Get predictions from each model
                for dataset_name, model in self.models.items():
                    # Scale the data
                    scaled_data = self.scalers[dataset_name].transform(batch)
                    
                    # Convert to PyTorch tensor
                    with torch.no_grad():
                        inputs = torch.FloatTensor(scaled_data)
                        outputs = model(inputs)
                        predictions = torch.softmax(outputs, dim=1)
                        predicted_classes = torch.argmax(predictions, dim=1)
                    
                    # Convert predictions to numpy for easier handling
                    predictions = predictions.numpy()
                    predicted_classes = predicted_classes.numpy()
                    
                    # Create threat entries
                    for j, (pred_class, pred_probs) in enumerate(zip(predicted_classes, predictions)):
                        severity = float(max(pred_probs))  # Convert to float for JSON serialization
                        
                        threat = {
                            'id': i + j,
                            'model': dataset_name,
                            'attack_type': 'Zero-Day' if pred_class == 2 else 'Anomaly' if pred_class == 1 else 'Normal',
                            'severity': severity,
                            'confidence': severity * 100,
                            'details': {
                                'raw_features': batch.iloc[j].to_dict(),
                                'prediction_probabilities': {
                                    'normal': float(pred_probs[0]),
                                    'anomaly': float(pred_probs[1]),
                                    'zero_day': float(pred_probs[2])
                                }
                            }
                        }
                        threats.append(threat)
            
            # Sort threats by severity
            threats.sort(key=lambda x: x['severity'], reverse=True)
            
            return {
                'success': True,
                'threats': threats,
                'stats': {
                    'total_samples': len(df),
                    'detected_threats': len([t for t in threats if t['attack_type'] != 'Normal']),
                    'models_used': list(self.models.keys())
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing test data: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# Initialize Flask app
app = Flask(__name__, static_folder='static')
detector = ThreatDetector()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/test', methods=['POST'])
def test():
    data = request.get_json()
    test_data_path = data.get('test_data_path', DEFAULT_TEST_PATH)
    max_samples = int(data.get('max_samples', 100))
    
    result = detector.detect_threats(test_data_path, max_samples)
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5000, debug=True) 