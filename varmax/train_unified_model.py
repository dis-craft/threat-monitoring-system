import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization, Activation, Concatenate
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
import joblib
import time
import json
import argparse
import matplotlib.pyplot as plt
from datetime import datetime

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

# Dataset paths
DATASET_PATHS = {
    'kdd': 'KDD_Train_preprocessed.csv',
    'train': 'preprocessed_train_data.csv',
    'unsw': 'UNSW_NB15_train_preprocessed.csv'
}

TEST_PATHS = {
    'kdd': 'KDD_Test_preprocessed.csv',
    'train': 'preprocessed_test_data.csv',
    'unsw': 'UNSW_NB15_test_preprocessed.csv'
}

class VARMAXModel:
    def __init__(self, input_size, hidden_size=256, num_classes=2, dropout_rate=0.3):
        """
        TensorFlow/Keras implementation of the VARMAX model
        
        Args:
            input_size: Number of input features
            hidden_size: Size of hidden layers
            num_classes: Number of output classes
            dropout_rate: Dropout rate
        """
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_classes = num_classes
        self.dropout_rate = dropout_rate
        self.model = self._build_model()
        
    def _build_model(self):
        """Build the Keras model with the VARMAX architecture"""
        inputs = Input(shape=(self.input_size,))
        
        # Input normalization
        x = BatchNormalization()(inputs)
        
        # First hidden layer
        x = Dense(self.hidden_size, kernel_initializer='he_normal')(x)
        x = BatchNormalization()(x)
        x = Activation('relu')(x)
        x = Dropout(self.dropout_rate)(x)
        
        # Second hidden layer
        x = Dense(self.hidden_size // 2, kernel_initializer='he_normal')(x) # 256 -> 128
        x = BatchNormalization()(x)
        x = Activation('relu')(x)
        x = Dropout(self.dropout_rate)(x)
        
        # Third hidden layer
        x = Dense(self.hidden_size // 4, kernel_initializer='he_normal')(x) # 128 -> 64
        x = BatchNormalization()(x)
        x = Activation('relu')(x)
        x = Dropout(self.dropout_rate)(x)
        
        # Output layer
        outputs = Dense(self.num_classes, activation='softmax', kernel_initializer='he_normal')(x)
        
        # Create model
        model = Model(inputs=inputs, outputs=outputs)
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model

class UnifiedTrainer:
    def __init__(self, model_dir='unified_model', batch_size=1024, test_size=0.2, random_state=42):
        """
        Trainer for the unified VARMAX model
        
        Args:
            model_dir: Directory to save models
            batch_size: Batch size for training
            test_size: Test split ratio
            random_state: Random seed
        """
        self.model_dir = model_dir
        self.batch_size = batch_size
        self.test_size = test_size
        self.random_state = random_state
        self.preprocessors = {}
        self.models = {}
        self.dataset_stats = {}
        self.unified_model = None
        
        # Create model directory if it doesn't exist
        os.makedirs(self.model_dir, exist_ok=True)
        
    def load_dataset(self, filepath, dataset_name, max_samples=None):
        """
        Load and preprocess a dataset
        
        Args:
            filepath: Path to CSV file
            dataset_name: Name of the dataset
            max_samples: Maximum number of samples to load (for debugging)
            
        Returns:
            Dictionary with train/test data
        """
        print(f"\nLoading {dataset_name} dataset from {filepath}")
        try:
            if max_samples:
                df = pd.read_csv(filepath, nrows=max_samples)
            else:
                df = pd.read_csv(filepath)
                
            print(f"Dataset loaded successfully. Shape: {df.shape}")
            
            # Assume the last column is the label
            features = df.iloc[:, :-1]
            labels = df.iloc[:, -1].astype(int)
            
            # Get dataset statistics
            n_features = features.shape[1]
            n_classes = len(np.unique(labels))
            class_distribution = {int(k): int(v) for k, v in labels.value_counts().items()}
            
            self.dataset_stats[dataset_name] = {
                'n_features': n_features,
                'n_classes': n_classes,
                'class_distribution': class_distribution,
                'feature_names': list(features.columns)
            }
            
            print(f"Dataset stats: {n_features} features, {n_classes} classes")
            print(f"Class distribution: {class_distribution}")
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=self.test_size, 
                random_state=self.random_state, stratify=labels
            )
            
            # Standardize the data
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Save the scaler
            self.preprocessors[dataset_name] = scaler
            scaler_path = os.path.join(self.model_dir, f"{dataset_name}_scaler.joblib")
            joblib.dump(scaler, scaler_path)
            print(f"Saved scaler to {scaler_path}")
            
            # Convert labels to categorical (one-hot encoding)
            y_train_cat = to_categorical(y_train, num_classes=n_classes)
            y_test_cat = to_categorical(y_test, num_classes=n_classes)
            
            return {
                'X_train': X_train_scaled,
                'X_test': X_test_scaled,
                'y_train': y_train_cat,
                'y_test': y_test_cat,
                'y_train_raw': y_train,
                'y_test_raw': y_test
            }
        except Exception as e:
            print(f"Error loading dataset {dataset_name}: {str(e)}")
            raise
    
    def train_model(self, dataset_name, dataset, epochs=50):
        """
        Train a model for a specific dataset
        
        Args:
            dataset_name: Name of the dataset
            dataset: Dictionary with train/test data
            epochs: Number of epochs to train
            
        Returns:
            Training history
        """
        print(f"\nTraining model for {dataset_name}")
        
        # Get dataset stats
        n_features = self.dataset_stats[dataset_name]['n_features']
        n_classes = self.dataset_stats[dataset_name]['n_classes']
        
        # Create model
        model = VARMAXModel(
            input_size=n_features,
            hidden_size=256,
            num_classes=n_classes,
            dropout_rate=0.3
        )
        
        # Print model summary
        model.model.summary()
        
        # Set up callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=5,
                restore_best_weights=True,
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=3,
                min_lr=1e-6,
                verbose=1
            ),
            ModelCheckpoint(
                filepath=os.path.join(self.model_dir, f"{dataset_name}_best_model.h5"),
                monitor='val_accuracy',
                save_best_only=True,
                verbose=1
            )
        ]
        
        # Train the model
        history = model.model.fit(
            dataset['X_train'], dataset['y_train'],
            validation_data=(dataset['X_test'], dataset['y_test']),
            epochs=epochs,
            batch_size=self.batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Save the final model
        model_path = os.path.join(self.model_dir, f"{dataset_name}_model.h5")
        model.model.save(model_path)
        print(f"Saved model to {model_path}")
        
        # Store the model in memory
        self.models[dataset_name] = model.model
        
        # Evaluate the model
        loss, accuracy = model.model.evaluate(dataset['X_test'], dataset['y_test'])
        print(f"\nTest results for {dataset_name}:")
        print(f"Loss: {loss:.4f}")
        print(f"Accuracy: {accuracy:.4f}")
        
        return history
    
    def train_all_datasets(self):
        """Train models for all datasets"""
        all_histories = {}
        
        for name, path in DATASET_PATHS.items():
            print(f"\n{'='*40}")
            print(f"Training on {name} dataset")
            print(f"{'='*40}")
            
            try:
                # For debugging, use max_samples=10000 to train faster
                dataset = self.load_dataset(path, name)
                history = self.train_model(name, dataset)
                all_histories[name] = history.history
            except Exception as e:
                print(f"Error training on {name} dataset: {str(e)}")
                continue
        
        # Save dataset statistics
        stats_path = os.path.join(self.model_dir, "dataset_stats.joblib")
        joblib.dump(self.dataset_stats, stats_path)
        print(f"Saved dataset statistics to {stats_path}")
        
        return all_histories
    
    def create_anomaly_detectors(self):
        """Create anomaly detection models for each dataset"""
        anomaly_detectors = {}
        
        for name in DATASET_PATHS.keys():
            print(f"Creating anomaly detectors for {name}")
            
            # Isolation Forest
            iso_model = IsolationForest(contamination=0.05, random_state=42)
            anomaly_detectors[f"{name}_isoforest"] = iso_model
            
            # LOF
            lof_model = LocalOutlierFactor(n_neighbors=20, contamination=0.05)
            anomaly_detectors[f"{name}_lof"] = lof_model
            
            # Save the models
            joblib.dump(iso_model, os.path.join(self.model_dir, f"{name}_isoforest.joblib"))
            # LOF is not saved because it's fitted at prediction time
        
        return anomaly_detectors
    
    def create_unified_model(self):
        """Create and save metadata for the unified detection system"""
        unified_info = {
            'datasets': list(self.dataset_stats.keys()),
            'models': {
                name: {
                    'path': f"{name}_model.h5",
                    'features': self.dataset_stats[name]['n_features'],
                    'classes': self.dataset_stats[name]['n_classes'],
                    'feature_names': self.dataset_stats[name]['feature_names'][:20]  # First 20 features
                } for name in self.dataset_stats.keys()
            },
            'anomaly_detectors': {
                f"{name}_isoforest": f"{name}_isoforest.joblib" for name in self.dataset_stats.keys()
            },
            'timestamp': datetime.now().strftime('%Y%m%d_%H%M%S')
        }
        
        # Save the unified info
        with open(os.path.join(self.model_dir, "unified_model_info.json"), 'w') as f:
            json.dump(unified_info, f, indent=2)
            
        print(f"Saved unified model info to {os.path.join(self.model_dir, 'unified_model_info.json')}")
        return unified_info

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Train a unified VARMAX model')
    parser.add_argument('--batch_size', type=int, default=1024, help='Batch size for training')
    parser.add_argument('--epochs', type=int, default=20, help='Number of epochs to train')
    parser.add_argument('--model_dir', type=str, default='unified_model', help='Directory to save models')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode with limited samples')
    args = parser.parse_args()
    
    # Create trainer
    trainer = UnifiedTrainer(
        model_dir=args.model_dir,
        batch_size=args.batch_size,
        test_size=0.2,
        random_state=42
    )
    
    # Train all models
    start_time = time.time()
    trainer.train_all_datasets()
    
    # Create and save anomaly detectors
    trainer.create_anomaly_detectors()
    
    # Create unified model info
    trainer.create_unified_model()
    
    total_time = time.time() - start_time
    print(f"\nTotal training time: {total_time:.2f} seconds")
    print(f"Unified model saved to {args.model_dir}")

if __name__ == "__main__":
    main() 