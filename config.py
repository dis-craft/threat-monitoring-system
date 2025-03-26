import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data generation settings
DATA_PATH = os.path.join(BASE_DIR, 'data/generated_logs/logs.csv')
NUM_RECORDS = 10000
ANOMALY_RATIO = 0.05  # 5% anomalous traffic

# Model settings
MODEL_PATH = os.path.join(BASE_DIR, 'data/trained_models/anomaly_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'data/trained_models/scaler.pkl')

# Detection settings
THRESHOLD_MULTIPLIER = 2  # Mean + 2*std
BATCH_SIZE = 100  # For simulated real-time processing
SLEEP_INTERVAL = 5  # Seconds between batches in simulation 