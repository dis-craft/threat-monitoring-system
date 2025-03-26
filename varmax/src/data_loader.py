from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from torch.utils.data import DataLoader, TensorDataset, Dataset
import pandas as pd
import numpy as np
import torch
import os
import joblib
from colorama import Fore, Style
from datetime import datetime

class NetworkDataset(Dataset):
    def __init__(self, features, labels):
        # Convert pandas Series to numpy array if needed
        if isinstance(labels, pd.Series):
            labels = labels.values
        
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)
        
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

class NetworkTrafficDataset(Dataset):
    def __init__(self, features, labels):
        self.features = features
        self.labels = labels
        
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

class MultiDatasetLoader:
    def __init__(self, batch_size=64, test_size=0.2, random_state=42):
        self.batch_size = batch_size
        self.test_size = test_size
        self.random_state = random_state
        self.preprocessors = {}
        self.dataset_stats = {}
        
    def _load_dataset(self, filepath, dataset_name):
        print(f"\nLoading {dataset_name} dataset from {filepath}")
        try:
            df = pd.read_csv(filepath)
            print(f"Dataset loaded successfully. Shape: {df.shape}")
            
            # Assume the last column is the label
            features = df.iloc[:, :-1]
            labels = df.iloc[:, -1].astype(int)
            
            # Get dataset statistics
            n_features = features.shape[1]
            n_classes = len(labels.unique())
            class_distribution = labels.value_counts().to_dict()
            
            self.dataset_stats[dataset_name] = {
                'n_features': n_features,
                'n_classes': n_classes,
                'class_distribution': class_distribution
            }
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=self.test_size, random_state=self.random_state
            )
            
            # Standardize the data
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Save the scaler
            self.preprocessors[dataset_name] = scaler
            
            # Create PyTorch tensors
            X_train_tensor = torch.FloatTensor(X_train_scaled)
            X_test_tensor = torch.FloatTensor(X_test_scaled)
            y_train_tensor = torch.LongTensor(y_train.values)
            y_test_tensor = torch.LongTensor(y_test.values)
            
            # Create datasets
            train_dataset = NetworkTrafficDataset(X_train_tensor, y_train_tensor)
            test_dataset = NetworkTrafficDataset(X_test_tensor, y_test_tensor)
            
            # Create dataloaders
            train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)
            test_loader = DataLoader(test_dataset, batch_size=self.batch_size, shuffle=False)
            
            return {
                'train': train_loader,
                'test': test_loader,
                'X_train': X_train_scaled,
                'X_test': X_test_scaled,
                'y_train': y_train.values,
                'y_test': y_test.values
            }
        
        except Exception as e:
            print(f"Error loading dataset {dataset_name}: {e}")
            return None
    
    def load_all_datasets(self):
        # Define datasets to load - each item is (filepath, dataset_name)
        datasets = [
            ("KDD_Train_preprocessed.csv", "KDD"),
            ("UNSW_NB15_train_preprocessed.csv", "UNSW"),
            ("preprocessed_train_data.csv", "CICIDS")
        ]
        
        dataloaders = {}
        for filepath, dataset_name in datasets:
            if os.path.exists(filepath):
                result = self._load_dataset(filepath, dataset_name)
                if result:
                    dataloaders[dataset_name] = result
            else:
                print(f"Dataset file {filepath} not found.")
        
        # Save preprocessors
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.preprocessors, "models/preprocessing_objects.joblib")
        
        return dataloaders, self.dataset_stats
        
    def load_combined_dataset(self):
        """Load all datasets and combine them into a single dataset with standardized features"""
        print("\nLoading and combining all datasets...")
        dataloaders, _ = self.load_all_datasets()
        
        if not dataloaders:
            print("No datasets loaded successfully.")
            return None, None
            
        # Find the maximum number of features across all datasets
        max_features = max(stats['n_features'] for stats in self.dataset_stats.values())
        
        # Get total number of classes across all datasets
        all_classes = set()
        for dataset_name, info in self.dataset_stats.items():
            all_classes.update(range(info['n_classes']))
        num_classes = len(all_classes)
        
        # Initialize combined data containers
        X_train_combined = []
        y_train_combined = []
        X_test_combined = []
        y_test_combined = []
        
        # Collect data from each dataset
        for dataset_name, loaders in dataloaders.items():
            X_train = loaders['X_train']
            y_train = loaders['y_train']
            X_test = loaders['X_test']
            y_test = loaders['y_test']
            
            # Zero-pad features to match max_features
            if X_train.shape[1] < max_features:
                pad_width = ((0, 0), (0, max_features - X_train.shape[1]))
                X_train = np.pad(X_train, pad_width, mode='constant', constant_values=0)
                X_test = np.pad(X_test, pad_width, mode='constant', constant_values=0)
            
            # Add dataset index as a feature
            dataset_idx = list(dataloaders.keys()).index(dataset_name)
            X_train = np.hstack((X_train, np.full((X_train.shape[0], 1), dataset_idx)))
            X_test = np.hstack((X_test, np.full((X_test.shape[0], 1), dataset_idx)))
            
            # Append to combined data
            X_train_combined.append(X_train)
            y_train_combined.append(y_train)
            X_test_combined.append(X_test)
            y_test_combined.append(y_test)
        
        # Concatenate data
        X_train_combined = np.vstack(X_train_combined)
        y_train_combined = np.concatenate(y_train_combined)
        X_test_combined = np.vstack(X_test_combined)
        y_test_combined = np.concatenate(y_test_combined)
        
        # Create PyTorch tensors
        X_train_tensor = torch.FloatTensor(X_train_combined)
        X_test_tensor = torch.FloatTensor(X_test_combined)
        y_train_tensor = torch.LongTensor(y_train_combined)
        y_test_tensor = torch.LongTensor(y_test_combined)
        
        # Create datasets
        train_dataset = NetworkTrafficDataset(X_train_tensor, y_train_tensor)
        test_dataset = NetworkTrafficDataset(X_test_tensor, y_test_tensor)
        
        # Create dataloaders
        train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=self.batch_size, shuffle=False)
        
        combined_loaders = {
            'train': train_loader,
            'test': test_loader
        }
        
        combined_stats = {
            'n_features': max_features + 1,  # +1 for the dataset index feature
            'n_classes': num_classes,
            'datasets_included': list(dataloaders.keys())
        }
        
        print(f"Combined dataset created with {X_train_combined.shape[0]:,} training samples " +
              f"and {X_test_combined.shape[0]:,} test samples.")
        print(f"Features: {combined_stats['n_features']}, Classes: {combined_stats['n_classes']}")
        
        return combined_loaders, combined_stats

class DataLoaderModule:
    def __init__(self, max_samples_per_class=10000, batch_size=256, save_path="models"):
        self.max_samples_per_class = max_samples_per_class
        self.batch_size = batch_size
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.imputer = SimpleImputer(strategy='mean')
        self.save_path = save_path
        self.numeric_cols = None
        os.makedirs(save_path, exist_ok=True)
        
    def load_data(self, data_path='CICIDS2017_preprocessed.csv', validate=True, optimize=True, engineer_features=True):
        """Load and preprocess data with enhanced preprocessing options"""
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"The dataset file '{data_path}' was not found. Please make sure the dataset is in the current directory.")
        
        print(f"{Fore.GREEN}✔ Loading dataset: {data_path}{Style.RESET_ALL}")
        data = pd.read_csv(data_path)
        
        # Validate and clean the data
        if validate:
            data = self._validate_dataset(data)
            
        # Optimize memory usage
        if optimize:
            data = self._optimize_memory(data)
            
        # Feature engineering
        if engineer_features:
            data = self._feature_engineering(data)

        # Drop unnecessary columns if they exist
        columns_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Timestamp', 'src_ip', 'dst_ip']
        data.drop(columns=[col for col in columns_to_drop if col in data.columns], inplace=True)
        data.replace([np.inf, -np.inf], np.nan, inplace=True)
        data.dropna(inplace=True)

        # Define known and unknown classes
        known_classes = ['BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'DoS GoldenEye', 'DoS slowloris', 'Bot', 'FTP-Patator']
        unknown_classes = ['Web Attack – Brute Force']
        
        # Make column names lowercase
        data.columns = data.columns.str.lower()
        
        # Ensure we have a label column
        if 'label' not in data.columns:
            # Check for alternative label columns
            for alt_label in ['attack_type', 'class']:
                if alt_label in data.columns:
                    data = data.rename(columns={alt_label: 'label'})
                    break
        
        # Split data into known and unknown classes
        data_known = data[data['label'].isin(known_classes)].copy()
        data_unknown = data[data['label'].isin(unknown_classes)].copy()

        # Limit samples per class in the known data
        data_known = data_known.groupby('label').apply(
            lambda x: x.sample(n=min(len(x), self.max_samples_per_class), random_state=42)
        ).reset_index(drop=True)
        
        # Encode labels for known classes only
        y_known = self.label_encoder.fit_transform(data_known['label'])
        num_classes = len(self.label_encoder.classes_)
        unknown_label = num_classes  # Assign unknown class the next integer

        # Get numerical features
        features_known = data_known.drop('label', axis=1)
        features_unknown = data_unknown.drop('label', axis=1) if not data_unknown.empty else pd.DataFrame()
        
        self.numeric_cols = features_known.select_dtypes(include=np.number).columns.tolist()
        
        # Impute missing values
        features_known[self.numeric_cols] = self.imputer.fit_transform(features_known[self.numeric_cols])
        if not features_unknown.empty:
            features_unknown[self.numeric_cols] = self.imputer.transform(features_unknown[self.numeric_cols])
        
        # Standardize features
        X_known = self.scaler.fit_transform(features_known[self.numeric_cols])
        X_unknown = self.scaler.transform(features_unknown[self.numeric_cols]) if not features_unknown.empty else np.array([])

        # Split known data into training and test sets
        X_train, X_test_known, y_train, y_test_known = train_test_split(
            X_known, y_known, test_size=0.3, random_state=42, stratify=y_known
        )
        
        # Create combined test set with known and unknown classes
        if X_unknown.size > 0:
            X_test_combined = np.vstack((X_test_known, X_unknown))
            y_test_combined = np.concatenate((y_test_known, [unknown_label] * X_unknown.shape[0]))
        else:
            X_test_combined = X_test_known
            y_test_combined = y_test_known

        # Convert data to PyTorch tensors and create DataLoaders
        train_loader = DataLoader(
            TensorDataset(torch.tensor(X_train, dtype=torch.float32), torch.tensor(y_train, dtype=torch.long)),
            batch_size=self.batch_size, shuffle=True
        )
        
        test_loader = DataLoader(
            TensorDataset(torch.tensor(X_test_combined, dtype=torch.float32), torch.tensor(y_test_combined, dtype=torch.long)),
            batch_size=self.batch_size
        )
        
        # Save preprocessing artifacts
        self._save_preprocessing_objects()
        
        # Print class distribution
        self._analyze_class_distribution(y_train, y_test_combined)
        
        return train_loader, test_loader, self.label_encoder, num_classes, unknown_label, self.scaler
    
    def _validate_dataset(self, df):
        """Validate and clean the dataset"""
        # Convert column names to lowercase
        df.columns = df.columns.str.lower()
        
        # Ensure required columns exist
        required_columns = {'src_ip', 'dst_ip'}
        missing_ips = required_columns - set(df.columns)
        if missing_ips:
            print(f"{Fore.YELLOW}⚠ Dataset missing IP columns: {missing_ips}. Using placeholders.{Style.RESET_ALL}")
            for col in missing_ips:
                df[col] = '0.0.0.0' if 'ip' in col else 0
        
        # Handle label column
        if 'label' not in df.columns:
            # Check for alternative label columns
            for alt_label in ['attack_type', 'class']:
                if alt_label in df.columns:
                    df = df.rename(columns={alt_label: 'label'})
                    break
            
            if 'label' not in df.columns:
                raise ValueError("Dataset missing label column")
        
        # Process label column - handle as string first to avoid categorical issues
        df['label'] = df['label'].astype(str).replace({'nan': 'Unknown', 'None': 'Unknown'})
        
        # Fill missing values for numeric columns
        numeric_cols = df.select_dtypes(include=np.number).columns
        for col in numeric_cols:
            df[col] = df[col].fillna(0)
        
        # Fill missing values for non-numeric columns
        non_numeric_cols = df.select_dtypes(exclude=np.number).columns
        for col in non_numeric_cols:
            if col != 'label':  # Handle label separately
                df[col] = df[col].fillna('Unknown')
        
        return df
    
    def _optimize_memory(self, df):
        """Optimize memory usage of dataframe"""
        for col in df.columns:
            col_type = df[col].dtype.name
            if col_type == 'object':
                df[col] = df[col].astype('category')
            elif col_type == 'float64':
                df[col] = pd.to_numeric(df[col], downcast='float', errors='coerce').fillna(0)
            elif col_type == 'int64':
                df[col] = pd.to_numeric(df[col], downcast='integer', errors='coerce').fillna(0)
        return df
    
    def _feature_engineering(self, df):
        """Apply feature engineering to the dataset"""
        # Process timestamp column if it exists
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(np.int8)
                df['day_of_week'] = df['timestamp'].dt.dayofweek.fillna(0).astype(np.int8)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠ Timestamp error: {str(e)}{Style.RESET_ALL}")
            finally:
                df = df.drop(columns=['timestamp'], errors='ignore')
        
        return df
    
    def _save_preprocessing_objects(self):
        """Save preprocessing objects for later use"""
        preprocessing_path = os.path.join(self.save_path, "preprocessing_objects.joblib")
        joblib.dump({
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'imputer': self.imputer,
            'numeric_cols': self.numeric_cols
        }, preprocessing_path)
        print(f"{Fore.GREEN}✔ Preprocessing objects saved to: {preprocessing_path}{Style.RESET_ALL}")
    
    def _analyze_class_distribution(self, y_train, y_test):
        """Analyze class distribution in training and test sets"""
        print("\nClass Distribution Analysis:")
        train_counts = np.bincount(y_train)
        test_counts = np.bincount(y_test)
        
        print(f"{'Class':<10}{'Train Count':<15}{'Test Count':<15}{'Train %':<15}{'Test %':<15}")
        for i in range(max(len(train_counts), len(test_counts))):
            train_count = train_counts[i] if i < len(train_counts) else 0
            test_count = test_counts[i] if i < len(test_counts) else 0
            train_pct = (train_count/len(y_train))*100 if len(y_train) > 0 else 0
            test_pct = (test_count/len(y_test))*100 if len(y_test) > 0 else 0
            print(f"{i:<10}{train_count:<15}{test_count:<15}{train_pct:<15.2f}{test_pct:<15.2f}")
    
    def load_preprocessing_objects(self, path=None):
        """Load saved preprocessing objects"""
        if path is None:
            path = os.path.join(self.save_path, "preprocessing_objects.joblib")
        
        if os.path.exists(path):
            preproc_objects = joblib.load(path)
            self.scaler = preproc_objects['scaler']
            self.label_encoder = preproc_objects['label_encoder']
            self.imputer = preproc_objects['imputer']
            self.numeric_cols = preproc_objects['numeric_cols']
            print(f"{Fore.GREEN}✔ Loaded preprocessing objects from: {path}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}⚠ No preprocessing objects found at: {path}{Style.RESET_ALL}")
            return False
