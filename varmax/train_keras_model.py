import os
import numpy as np
import pandas as pd
from datetime import datetime
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential, load_model, save_model
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization, Activation
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint, ReduceLROnPlateau
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import joblib
import argparse

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

class KerasVarmaxModel:
    def __init__(self, input_size, hidden_size=128, num_classes=2, dropout_rate=0.3):
        """
        Keras implementation of the VARMAX model architecture
        
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
        """Build the Keras model with similar architecture to the PyTorch version"""
        model = Sequential([
            # Input normalization
            BatchNormalization(input_shape=(self.input_size,)),
            
            # First hidden layer
            Dense(self.hidden_size * 2, kernel_initializer='he_normal'),
            Activation('relu'),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            # Second hidden layer
            Dense(self.hidden_size, kernel_initializer='he_normal'),
            Activation('relu'),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            # Third hidden layer
            Dense(self.hidden_size // 2, kernel_initializer='he_normal'),
            Activation('relu'),
            Dropout(self.dropout_rate),
            BatchNormalization(),
            
            # Output layer
            Dense(self.num_classes, activation='softmax', kernel_initializer='he_normal')
        ])
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def summary(self):
        """Print model summary"""
        return self.model.summary()
    
    def save(self, filepath):
        """Save the model"""
        self.model.save(filepath)
        
    def load(self, filepath):
        """Load the model"""
        self.model = load_model(filepath)
        
class UnifiedTrainer:
    def __init__(self, model_dir='keras_models', batch_size=64, test_size=0.2, random_state=42):
        """
        Trainer for the Keras VARMAX model
        
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
        
        # Create model directory if it doesn't exist
        os.makedirs(self.model_dir, exist_ok=True)
        
    def load_dataset(self, filepath, dataset_name):
        """
        Load and preprocess a dataset
        
        Args:
            filepath: Path to CSV file
            dataset_name: Name of the dataset
            
        Returns:
            Dictionary with train/test data
        """
        print(f"\nLoading {dataset_name} dataset from {filepath}")
        try:
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
                'class_distribution': class_distribution
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
            joblib.dump(scaler, os.path.join(self.model_dir, f"{dataset_name}_scaler.joblib"))
            
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
    
    def train_model(self, dataset_name, dataset):
        """
        Train a model for a specific dataset
        
        Args:
            dataset_name: Name of the dataset
            dataset: Dictionary with train/test data
            
        Returns:
            Training history
        """
        print(f"\nTraining model for {dataset_name}")
        
        # Get dataset stats
        n_features = self.dataset_stats[dataset_name]['n_features']
        n_classes = self.dataset_stats[dataset_name]['n_classes']
        
        # Create model
        model = KerasVarmaxModel(
            input_size=n_features,
            hidden_size=128,
            num_classes=n_classes,
            dropout_rate=0.3
        )
        
        # Print model summary
        model.summary()
        
        # Set up callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
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
            epochs=100,
            batch_size=self.batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Save the final model
        model.save(os.path.join(self.model_dir, f"{dataset_name}_model.h5"))
        
        # Store the model in memory
        self.models[dataset_name] = model
        
        # Evaluate the model
        loss, accuracy = model.model.evaluate(dataset['X_test'], dataset['y_test'])
        print(f"\nTest results for {dataset_name}:")
        print(f"Loss: {loss:.4f}")
        print(f"Accuracy: {accuracy:.4f}")
        
        return history
    
    def plot_training_history(self, history, dataset_name):
        """Plot training history"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))
        
        # Plot accuracy
        ax1.plot(history.history['accuracy'])
        ax1.plot(history.history['val_accuracy'])
        ax1.set_title(f'{dataset_name} - Accuracy')
        ax1.set_ylabel('Accuracy')
        ax1.set_xlabel('Epoch')
        ax1.legend(['Train', 'Validation'], loc='upper left')
        
        # Plot loss
        ax2.plot(history.history['loss'])
        ax2.plot(history.history['val_loss'])
        ax2.set_title(f'{dataset_name} - Loss')
        ax2.set_ylabel('Loss')
        ax2.set_xlabel('Epoch')
        ax2.legend(['Train', 'Validation'], loc='upper left')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_dir, f"{dataset_name}_training_history.png"))
        plt.close()
    
    def train_all_datasets(self, dataset_paths):
        """
        Train models for all datasets
        
        Args:
            dataset_paths: Dictionary mapping dataset names to file paths
        """
        histories = {}
        
        for dataset_name, filepath in dataset_paths.items():
            print(f"\n{'='*50}")
            print(f"Processing dataset: {dataset_name}")
            print(f"{'='*50}")
            
            # Load and preprocess the dataset
            dataset = self.load_dataset(filepath, dataset_name)
            
            # Train the model
            history = self.train_model(dataset_name, dataset)
            
            # Plot training history
            self.plot_training_history(history, dataset_name)
            
            histories[dataset_name] = history
        
        return histories
    
    def save_unified_model(self):
        """Create and save a unified model that combines all models"""
        if not self.models:
            print("No models to unify. Train models first.")
            return
        
        # Create a directory for the unified model
        unified_dir = os.path.join(self.model_dir, "unified")
        os.makedirs(unified_dir, exist_ok=True)
        
        # Save each model to the unified directory
        for dataset_name, model in self.models.items():
            model.save(os.path.join(unified_dir, f"{dataset_name}_model.h5"))
            
        # Save preprocessors
        for dataset_name, preprocessor in self.preprocessors.items():
            joblib.dump(preprocessor, os.path.join(unified_dir, f"{dataset_name}_scaler.joblib"))
            
        # Save dataset stats
        joblib.dump(self.dataset_stats, os.path.join(unified_dir, "dataset_stats.joblib"))
        
        print(f"Unified model saved to {unified_dir}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Train VARMAX models with Keras')
    parser.add_argument('--kdd_path', type=str, 
                      default='C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\KDD_Train_preprocessed.csv',
                      help='Path to KDD dataset')
    parser.add_argument('--train_path', type=str, 
                      default='C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\preprocessed_train_data.csv',
                      help='Path to preprocessed train data')
    parser.add_argument('--unsw_path', type=str, 
                      default='C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\UNSW_NB15_train_preprocessed.csv',
                      help='Path to UNSW-NB15 dataset')
    parser.add_argument('--batch_size', type=int, default=64, help='Batch size for training')
    parser.add_argument('--test_size', type=float, default=0.2, help='Test split ratio')
    
    args = parser.parse_args()
    
    # Define dataset paths
    dataset_paths = {
        'kdd': args.kdd_path,
        'train': args.train_path,
        'unsw': args.unsw_path
    }
    
    # Initialize trainer
    trainer = UnifiedTrainer(
        batch_size=args.batch_size,
        test_size=args.test_size
    )
    
    # Train models
    trainer.train_all_datasets(dataset_paths)
    
    # Save unified model
    trainer.save_unified_model()
    
    print("\nTraining completed successfully!")

if __name__ == "__main__":
    main() 