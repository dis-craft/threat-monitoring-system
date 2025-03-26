import os
import json
import logging
import pandas as pd
import numpy as np
import argparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from unified_anomaly_detector import UnifiedAnomalyDetector
from pyod_detector import PyODDetector
from live_detection import LiveDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Default paths
DEFAULT_MODEL_DIR = 'unified_model'

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Initialize detectors (will be loaded in main)
unified_detector = None
pyod_detector = None

# Default detection parameters
detection_params = {
    'contamination': 0.1,  # Expected anomaly ratio
    'min_confidence': 0.6,  # Minimum confidence threshold
    'feature_importance_method': 'permutation',  # Method for feature importance
    'ensemble_method': 'weighted',  # Ensemble method for combining model predictions
    'anomaly_probability': 0.2,  # Probability of generating anomalous connections
    'batch_size': 50,  # Number of connections to process at once
    'duration': 30,  # Duration of live detection in seconds
    'interval': 0.5  # Time between batches
}

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('static', path)

@app.route('/api/datasets', methods=['GET'])
def get_datasets():
    """Get available datasets"""
    try:
        if not unified_detector or not unified_detector.dataset_stats:
            return jsonify({"error": "Detector not initialized"})
            
        datasets = [
            {
                "id": 0,
                "name": "Live Network Traffic",
                "path": "live_detection",
                "description": "Live network traffic simulation with both normal and anomalous patterns."
            },
            {
                "id": 1,
                "name": "KDD Dataset",
                "path": "kdd",
                "description": "KDD Cup 1999 dataset with various network intrusion attacks."
            },
            {
                "id": 2,
                "name": "UNSW-NB15 Dataset",
                "path": "unsw",
                "description": "UNSW-NB15 dataset with modern attack types and normal traffic."
            }
        ]
        
        return jsonify(datasets)
    except Exception as e:
        logger.error(f"Error in get_datasets: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/api/model_info', methods=['GET'])
def get_model_info():
    """Get information about the unified model"""
    try:
        if not unified_detector or not unified_detector.dataset_stats:
            return jsonify({"error": "Detector not initialized"})
            
        # Get model information
        model_info = {
            "name": "VARMAX Enhanced Detection Engine",
            "version": "2.0.0",
            "description": "Advanced anomaly detection model with ensemble approach",
            "datasets": [
                {
                    "name": "KDD Dataset",
                    "features": unified_detector.dataset_stats.get('kdd', {}).get('n_features', 0),
                    "classes": unified_detector.dataset_stats.get('kdd', {}).get('n_classes', 0),
                    "distribution": unified_detector.dataset_stats.get('kdd', {}).get('class_distribution', {})
                },
                {
                    "name": "Preprocessed Training Data",
                    "features": unified_detector.dataset_stats.get('train', {}).get('n_features', 0),
                    "classes": unified_detector.dataset_stats.get('train', {}).get('n_classes', 0),
                    "distribution": unified_detector.dataset_stats.get('train', {}).get('class_distribution', {})
                },
                {
                    "name": "UNSW-NB15 Dataset",
                    "features": unified_detector.dataset_stats.get('unsw', {}).get('n_features', 0),
                    "classes": unified_detector.dataset_stats.get('unsw', {}).get('n_classes', 0),
                    "distribution": unified_detector.dataset_stats.get('unsw', {}).get('class_distribution', {})
                }
            ],
            "model_architecture": "VARMAX Neural Network with Enhanced Ensemble Approach",
            "feature_engineering": "Standardization, batch normalization, and feature importance analysis",
            "anomaly_detection": "Weighted ensemble of deep learning and statistical models",
            "zero_day_detection": "Pattern recognition using model disagreement and feature importance"
        }
        
        return jsonify(model_info)
    except Exception as e:
        logger.error(f"Error in get_model_info: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/api/pyod_models', methods=['GET'])
def get_pyod_models():
    """Get information about available PyOD models"""
    try:
        models = [
            {
                "name": "Isolation Forest",
                "description": "Efficient for high-dimensional data, uses random partitioning to isolate anomalies",
                "weight": pyod_detector.model_weights.get('iforest', 1.0)
            },
            {
                "name": "Local Outlier Factor",
                "description": "Density-based detection that identifies samples with lower local density",
                "weight": pyod_detector.model_weights.get('lof', 0.8)
            },
            {
                "name": "K-Nearest Neighbors",
                "description": "Distance-based approach using nearest neighbor distance as anomaly score",
                "weight": pyod_detector.model_weights.get('knn', 0.7)
            },
            {
                "name": "HBOS",
                "description": "Histogram-based fast anomaly detection using univariate feature analysis",
                "weight": pyod_detector.model_weights.get('hbos', 0.6)
            },
            {
                "name": "ECOD",
                "description": "Empirical cumulative distribution-based outlier detection",
                "weight": pyod_detector.model_weights.get('ecod', 0.9)
            }
        ]
        
        return jsonify(models)
    except Exception as e:
        logger.error(f"Error in get_pyod_models: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/api/detection_params', methods=['GET', 'POST'])
def detection_params_endpoint():
    """Get or update detection parameters"""
    global detection_params
    
    if request.method == 'GET':
        # Return current parameters
        return jsonify(detection_params)
    else:
        # Update parameters
        try:
            data = request.json
            
            # Update parameters if provided
            for key in data:
                if key in detection_params:
                    if isinstance(detection_params[key], float):
                        detection_params[key] = float(data[key])
                    elif isinstance(detection_params[key], int):
                        detection_params[key] = int(data[key])
                    else:
                        detection_params[key] = data[key]
                
            # Apply to PyOD detector
            if pyod_detector:
                if hasattr(pyod_detector, 'contamination'):
                    pyod_detector.contamination = detection_params['contamination']
                if hasattr(pyod_detector, 'min_confidence_threshold'):
                    pyod_detector.min_confidence_threshold = detection_params['min_confidence']
                if hasattr(pyod_detector, 'feature_importance_method'):
                    pyod_detector.feature_importance_method = detection_params['feature_importance_method']
                if hasattr(pyod_detector, 'ensemble_method'):
                    pyod_detector.ensemble_method = detection_params['ensemble_method']
            
            return jsonify({"success": True, "params": detection_params})
        except Exception as e:
            logger.error(f"Error updating detection parameters: {str(e)}")
            return jsonify({"error": str(e)})

@app.route('/api/live_detection', methods=['POST'])
def live_detection():
    """Detect anomalies in live data"""
    try:
        # Get parameters from request
        data = request.json
        dataset_name = data.get('dataset_name', 'kdd')
        anomaly_probability = float(data.get('anomaly_probability', detection_params['anomaly_probability']))
        batch_size = int(data.get('batch_size', detection_params['batch_size']))
        duration = float(data.get('duration', detection_params['duration']))
        interval = float(data.get('interval', detection_params['interval']))
        
        logger.info(f"Starting live detection with {dataset_name} dataset, {anomaly_probability} anomaly probability")
        
        # Initialize live detector
        detector = LiveDetector(
            dataset_name=dataset_name,
            anomaly_probability=anomaly_probability,
            batch_size=batch_size
        )
        
        # Start detection
        results = detector.start_detection(interval=interval, duration=duration)
        
        # Load saved detection history
        detection_history = []
        if detector.latest_history_file and os.path.exists(detector.latest_history_file):
            try:
                with open(detector.latest_history_file, 'r') as f:
                    detection_history = json.load(f)
            except Exception as e:
                logger.error(f"Error loading detection history: {str(e)}")
        
        return jsonify({
            "success": True,
            "results": results,
            "message": f"Live detection completed with {results['anomalies']} anomalies detected",
            "detection_history": detection_history[:100],  # Limit to 100 records
            "dataset": dataset_name
        })
    except Exception as e:
        logger.error(f"Error in live detection: {str(e)}")
        return jsonify({"error": str(e)})

def main():
    """Initialize detectors and start the server"""
    global unified_detector, pyod_detector
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VARMAX Unified Detection Server')
    parser.add_argument('--model_dir', type=str, default=DEFAULT_MODEL_DIR, help='Directory containing model data')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    try:
        # Initialize the unified detector
        unified_detector = UnifiedAnomalyDetector(model_dir=args.model_dir)
        logger.info(f"Unified detector initialized with model directory: {args.model_dir}")
        
        # Initialize the PyOD detector
        pyod_detector = PyODDetector(model_dir=args.model_dir)
        
        # Apply default parameters from global detection_params
        pyod_detector.contamination = detection_params['contamination']
        pyod_detector.min_confidence_threshold = detection_params['min_confidence']
        pyod_detector.feature_importance_method = detection_params['feature_importance_method']
        pyod_detector.ensemble_method = detection_params['ensemble_method']
        
        logger.info(f"PyOD detector initialized with model directory: {args.model_dir}")
    except Exception as e:
        logger.error(f"Error initializing detector: {str(e)}")
    
    # Start the server
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main() 