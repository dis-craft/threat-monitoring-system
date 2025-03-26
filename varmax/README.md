# VARMAX: Advanced Network Anomaly Detection System

This project implements an ensemble-based anomaly detection system for network security, combining deep learning models with traditional anomaly detection techniques.

## Features

- **Unified Model Architecture**: VARMAX neural network with batch normalization
- **Ensemble Approach**: Combines deep learning with traditional anomaly detection techniques
- **Zero-Day Detection**: Identifies unknown threats based on model disagreement
- **Feature Importance**: Explains which network features contribute to detections
- **Multi-Dataset Training**: Supports KDD, UNSW-NB15, and custom network data
- **Modern UI Dashboard**: Interactive visualization of threats and statistics

## Quick Start

1. Install dependencies:
```
pip install tensorflow scikit-learn pandas numpy joblib matplotlib flask flask-cors shap tqdm
```

2. Run the unified system:
```
python run_unified.py --debug
```

3. Open the dashboard in your browser:
```
http://localhost:5000
```

## System Architecture

The VARMAX system uses a multi-layer approach to detect anomalies:

1. **Neural Network Models**: Deep learning models trained on specific datasets
2. **Unsupervised Anomaly Detection**: Isolation Forest and Local Outlier Factor
3. **Ensemble Voting**: Combines predictions from all models
4. **Zero-Day Detection**: Identifies patterns flagged by anomaly detectors but missed by trained models

## Usage

### Running the System

```
python run_unified.py [options]
```

Options:
- `--train`: Train/create models first
- `--debug`: Run in debug mode with hot reloading
- `--port PORT`: Specify server port (default: 5000)

### Using the Dashboard

1. **Select Test Data**: Choose from available datasets or upload your own
2. **Set Analysis Parameters**: Specify max samples and model to use
3. **Run Analysis**: Click "Run Analysis" to process the data
4. **Explore Results**: View threat distribution, risk assessment, and detailed threat information
5. **Filter and Sort**: Use the filters to focus on specific threat types

## Implementation Details

### Model Architecture

The VARMAX neural network architecture consists of:
- Input batch normalization
- Three hidden layers (256→128→64 neurons)
- ReLU activation with dropout (0.3)
- Batch normalization between layers
- Softmax output layer

### Datasets

The system is designed to work with three major datasets:
- **KDD Cup 1999**: Classic network intrusion detection dataset
- **UNSW-NB15**: Modern attack types and normal traffic
- **Custom Network Data**: Your own preprocessed network traffic data

### Zero-Day Detection

Zero-day threats are detected through model disagreement:
1. If deep learning models classify traffic as normal
2. But anomaly detectors (Isolation Forest or LOF) flag it as suspicious
3. It is classified as a potential zero-day threat

## Advanced Usage

### Training Your Own Models

To train models on your own data:
```
python train_unified_model.py --batch_size 1024 --epochs 50 --model_dir unified_model
```

### Using the API Directly

The system exposes REST APIs for integration with other tools:
- `POST /api/test`: Run detection on a dataset
- `POST /api/live_detection`: Analyze live network data
- `GET /api/datasets`: List available datasets
- `GET /api/model_info`: Get model information

## Troubleshooting

- **Missing dependencies**: Ensure all required packages are installed
- **Model loading errors**: Check that model files exist in the `unified_model` directory
- **Data format issues**: Ensure your data is properly formatted (CSV with features and a label column)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 