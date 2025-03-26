# Unified VARMAX Model for Network Anomaly Detection

This project implements an advanced ensemble model for network anomaly detection that combines multiple machine learning techniques to detect both known anomalies and zero-day threats.

## Features

- **Unified Model Architecture**: VARMAX neural network with batch normalization, trained on multiple datasets
- **Ensemble Approach**: Combines deep learning with traditional anomaly detection techniques
- **Zero-Day Detection**: Identifies unknown threats based on model disagreement
- **Feature Importance**: Explains which network features contribute to detections
- **Multi-Dataset Training**: Trained on three major network security datasets
- **Risk Assessment**: Provides detailed risk analysis with confidence scores

## Datasets

The model is trained on three major datasets:

1. **KDD Cup 1999**: Classic network intrusion detection dataset
2. **Preprocessed Training Data**: General network traffic data
3. **UNSW-NB15**: Modern attack types and normal traffic

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Training the Unified Model

To train the unified VARMAX model on all three datasets:

```bash
python train_unified_model.py --batch_size 1024 --epochs 20 --model_dir unified_model
```

Options:
- `--batch_size`: Batch size for training (default: 1024)
- `--epochs`: Number of epochs to train (default: 20)
- `--model_dir`: Directory to save models (default: unified_model)
- `--debug`: Run in debug mode with limited samples

Training can take several hours depending on your hardware. For quick testing, use the `--debug` flag.

## Running Anomaly Detection

To detect anomalies in a test dataset:

```bash
python unified_anomaly_detector.py --test_data preprocessed_test_data.csv --max_samples 100
```

Options:
- `--model_dir`: Directory with trained models (default: unified_model)
- `--test_data`: Path to test data CSV file
- `--dataset`: Dataset to use for detection (kdd, train, unsw, or None for ensemble)
- `--max_samples`: Maximum number of samples to analyze (default: 100)
- `--output_dir`: Directory to save results (default: results)

## Running the Web Server

To start the anomaly detection web server:

```bash
python unified_server.py --port 5000 --debug
```

Options:
- `--model_dir`: Directory with trained models (default: unified_model)
- `--host`: Host to run the server on (default: 0.0.0.0)
- `--port`: Port to run the server on (default: 5000)
- `--debug`: Run the server in debug mode

Once the server is running, open your browser and navigate to http://localhost:5000 to access the dashboard.

## API Endpoints

The server provides the following API endpoints:

- `GET /api/datasets`: List available datasets
- `GET /api/model_info`: Get information about the unified model
- `POST /api/test`: Run anomaly detection on test data
- `POST /api/live_detection`: Detect anomalies in live data

## Understanding Detection Results

The detection results include:

- **Threat Distribution**: Percentage breakdown of normal, anomaly, and zero-day threats
- **Risk Assessment**: Overall risk level based on the threat distribution
- **Detailed Threats**: List of detected threats with confidence scores
- **Feature Importance**: Top features contributing to each detection

## Zero-Day Threat Detection

The model identifies zero-day threats using ensemble disagreement:

1. If the deep learning model classifies traffic as normal
2. But anomaly detectors (Isolation Forest or LOF) flag it as suspicious
3. It is labeled as a potential zero-day threat

This approach helps identify novel attacks that weren't present in the training data.

## Model Architecture

The VARMAX model uses a neural network with:

- Input batch normalization
- Three hidden layers (256→128→64 neurons)
- ReLU activation with dropout (0.3)
- Batch normalization between layers
- Softmax output layer

This architecture is combined with Isolation Forest and Local Outlier Factor (LOF) for ensemble predictions.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 