import os
import json
import logging
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, send_from_directory
from detect_anomalies_advanced import detect_anomalies
from pyod_detector import PyODDetector
from flask_cors import CORS

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TEST_PATH = 'data/preprocessed_test_data.csv'

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS

# Initialize PyOD detector
pyod_detector = PyODDetector(model_dir='unified_model')

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/test', methods=['POST'])
def test():
    try:
        data = request.get_json()
        test_data_path = data.get('test_data_path', DEFAULT_TEST_PATH)
        max_samples = int(data.get('max_samples', 100))
        use_pyod = data.get('use_pyod', True)  # Default to using PyOD
        dataset_name = data.get('dataset_name')
        
        logger.info(f"Running test on {test_data_path} with max_samples={max_samples}, use_pyod={use_pyod}")
        
        if use_pyod:
            # Run detection using PyOD
            result = pyod_detector.detect_threats(test_data_path, dataset_name, max_samples)
            
            # Format response
            response = {
                'success': True,
                'pyod': True,
                'result': result
            }
        else:
            # Run the original advanced detection
            result = detect_anomalies(test_data_path, max_samples)
            
            # Get ensemble threats only for the UI
            ensemble_threats = [t for t in result['threats'] if t.get('is_ensemble', False)]
            
            # Format the response for the UI
            response = {
                'success': True,
                'pyod': False,
                'threats': ensemble_threats,
                'stats': result['stats']
            }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in test endpoint: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/pyod', methods=['POST'])
def pyod_test():
    try:
        data = request.get_json()
        test_data_path = data.get('test_data_path', DEFAULT_TEST_PATH)
        max_samples = int(data.get('max_samples', 100))
        dataset_name = data.get('dataset_name')
        
        logger.info(f"Running PyOD test on {test_data_path} with max_samples={max_samples}, dataset={dataset_name}")
        
        # Run detection using PyOD
        result = pyod_detector.detect_threats(test_data_path, dataset_name, max_samples)
        
        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        logger.error(f"Error in pyod_test endpoint: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/datasets', methods=['GET'])
def get_datasets():
    datasets = [
        {
            'id': 'train',
            'name': 'TRAIN Dataset',
            'path': 'data/preprocessed_test_data.csv',
            'description': 'Primary test dataset with network traffic patterns'
        },
        {
            'id': 'kdd',
            'name': 'KDD Test Dataset',
            'path': 'data/KDD_Test_preprocessed.csv',
            'description': 'Industry standard for network intrusion detection'
        },
        {
            'id': 'unsw',
            'name': 'UNSW-NB15 Test Dataset',
            'path': 'data/UNSW_NB15_test_preprocessed.csv',
            'description': 'Modern dataset with various attack types'
        }
    ]
    
    return jsonify(datasets)

@app.route('/api/pyod_models', methods=['GET'])
def get_pyod_models():
    """Returns information about available PyOD models"""
    models = [
        {
            'id': 'iforest',
            'name': 'Isolation Forest',
            'description': 'Effective for high-dimensional data and noisy datasets'
        },
        {
            'id': 'lof',
            'name': 'Local Outlier Factor',
            'description': 'Identifies samples that have a substantially lower density than their neighbors'
        },
        {
            'id': 'knn',
            'name': 'K Nearest Neighbors',
            'description': 'Detects outliers based on distance to k-nearest neighbors'
        },
        {
            'id': 'hbos',
            'name': 'Histogram-based Outlier Score',
            'description': 'Fast algorithm using histograms for outlier detection'
        },
        {
            'id': 'ecod',
            'name': 'Empirical Cumulative Distribution',
            'description': 'Parameter-free method that uses empirical CDF for detection'
        },
        {
            'id': 'feature_bagging',
            'name': 'Feature Bagging',
            'description': 'Ensemble method that uses random feature subsets'
        }
    ]
    
    return jsonify(models)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
