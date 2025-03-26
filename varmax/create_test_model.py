import os
import numpy as np
import joblib
import json
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, BatchNormalization, Dropout
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Create model directory
model_dir = 'unified_model'
os.makedirs(model_dir, exist_ok=True)

print("Creating test models...")

# Define dataset statistics for test model
dataset_stats = {
    'kdd': {
        'n_features': 41,
        'n_classes': 5,
        'class_distribution': {0: 97278, 1: 391458, 2: 4107, 3: 52, 4: 2},
        'feature_names': [f'feature_kdd_{i}' for i in range(41)]
    },
    'train': {
        'n_features': 78,
        'n_classes': 2,
        'class_distribution': {0: 972780, 1: 27220},
        'feature_names': [f'feature_train_{i}' for i in range(78)]
    },
    'unsw': {
        'n_features': 44,
        'n_classes': 10,
        'class_distribution': {0: 56000, 1: 6000, 2: 4000, 3: 3000, 4: 2000, 5: 1000, 6: 500, 7: 300, 8: 150, 9: 50},
        'feature_names': [f'feature_unsw_{i}' for i in range(44)]
    }
}

# Save dataset statistics
joblib.dump(dataset_stats, os.path.join(model_dir, 'dataset_stats.joblib'))
print(f"Saved dataset statistics to {os.path.join(model_dir, 'dataset_stats.joblib')}")

# Create and save actual models and scalers for each dataset
for dataset_name, stats in dataset_stats.items():
    print(f"Creating model files for {dataset_name}")
    
    # Get parameters
    n_features = stats['n_features']
    n_classes = stats['n_classes']
    
    # Create a simple Keras model
    model = Sequential([
        BatchNormalization(input_shape=(n_features,)),
        Dense(256, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(128, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(64, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),
        Dense(n_classes, activation='softmax')
    ])
    
    # Compile the model
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    # Create dummy data for model.fit
    dummy_X = np.random.rand(1000, n_features)
    dummy_y = np.random.randint(0, n_classes, size=(1000,))
    
    # Fit model with just one epoch
    model.fit(dummy_X, dummy_y, epochs=1, verbose=0)
    
    # Save the model
    model_path = os.path.join(model_dir, f"{dataset_name}_model.h5")
    model.save(model_path)
    print(f"Saved model to {model_path}")
    
    # Create and save scaler
    scaler = StandardScaler()
    scaler.fit(dummy_X)
    scaler_path = os.path.join(model_dir, f"{dataset_name}_scaler.joblib")
    joblib.dump(scaler, scaler_path)
    print(f"Saved scaler to {scaler_path}")
    
    # Create and save isolation forest
    iso_forest = IsolationForest(random_state=42, contamination=0.1)
    iso_forest.fit(dummy_X)
    iso_path = os.path.join(model_dir, f"{dataset_name}_isoforest.joblib")
    joblib.dump(iso_forest, iso_path)
    print(f"Saved isolation forest to {iso_path}")

# Create a simple unified model info file
unified_info = {
    'datasets': list(dataset_stats.keys()),
    'models': {
        name: {
            'path': f"{name}_model.h5",
            'features': dataset_stats[name]['n_features'],
            'classes': dataset_stats[name]['n_classes'],
            'feature_names': dataset_stats[name]['feature_names'][:20]  # First 20 features
        } for name in dataset_stats.keys()
    },
    'anomaly_detectors': {
        f"{name}_isoforest": f"{name}_isoforest.joblib" for name in dataset_stats.keys()
    },
    'timestamp': '20250320_101010'
}

with open(os.path.join(model_dir, "unified_model_info.json"), 'w') as f:
    json.dump(unified_info, f, indent=2)
print(f"Saved unified model info to {os.path.join(model_dir, 'unified_model_info.json')}")

# Now create a preprocessing helper for the KDD dataset to fix the label issue
print("\nCreating KDD preprocessing helper...")

kdd_preprocess_code = '''
import pandas as pd
import os
import sys

def preprocess_kdd_data(input_file, output_file=None):
    """
    Preprocess KDD data to convert string labels to numeric
    
    Args:
        input_file: Input CSV file
        output_file: Output CSV file (optional)
        
    Returns:
        Processed DataFrame
    """
    try:
        print(f"Loading data from {input_file}...")
        df = pd.read_csv(input_file)
        
        # Create a copy of the original labels
        if 'label' in df.columns:
            # Map text labels to numeric
            print("Converting string labels to numeric...")
            label_mapping = {
                'normal': 0,
                'attack': 1,
                # Add more mappings if needed
            }
            
            # Create a new column with numeric labels
            df['label_numeric'] = df['label'].map(lambda x: label_mapping.get(x, 1))
            
            # Replace the original label column
            df['original_label'] = df['label']
            df['label'] = df['label_numeric']
            df.drop('label_numeric', axis=1, inplace=True)
            
            print(f"Converted labels. Value counts:\\n{df['label'].value_counts()}")
            
        # Save to output file if specified
        if output_file:
            print(f"Saving preprocessed data to {output_file}...")
            df.to_csv(output_file, index=False)
            
        return df
    except Exception as e:
        print(f"Error preprocessing KDD data: {str(e)}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python preprocess_kdd.py input_file [output_file]")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    preprocess_kdd_data(input_file, output_file)
    print("Preprocessing complete!")
'''

# Save the preprocessing script
with open('preprocess_kdd.py', 'w') as f:
    f.write(kdd_preprocess_code)
print("Created preprocess_kdd.py to help with string labels")

print("\nTest model files created successfully!")
print("Note: These are simple models trained on random data for interface testing.")
print("For a real implementation, you would train on actual network traffic data.")
print("\nFor testing the interface, you can run:")
print("python unified_server.py --debug")
print("Then open http://localhost:5000 in your browser.")
print("\nIf you have issues with string labels in KDD data, first preprocess it with:")
print("python preprocess_kdd.py KDD_Test_preprocessed.csv KDD_Test_preprocessed_fixed.csv") 