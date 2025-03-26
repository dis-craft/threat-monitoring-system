import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn import BatchNorm1d, Dropout, Linear

class VarMaxModel(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_classes=2, dropout_rate=0.3):
        super(VarMaxModel, self).__init__()
        
        # Feature extraction layers
        self.feature_extractor = nn.Sequential(
            BatchNorm1d(input_size),
            Linear(input_size, hidden_size * 2),
            nn.ReLU(),
            Dropout(dropout_rate),
            BatchNorm1d(hidden_size * 2),
            Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            Dropout(dropout_rate),
            BatchNorm1d(hidden_size)
        )
        
        # Attention layer (removed to simplify model)
        self.attention_layer = nn.Linear(hidden_size, 1)
        
        # Classification layers
        self.classifier = nn.Sequential(
            Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            Dropout(dropout_rate),
            BatchNorm1d(hidden_size // 2),
            Linear(hidden_size // 2, num_classes)
        )
        
        # Initialize weights
        self.apply(self._init_weights)
        
    def _init_weights(self, module):
        if isinstance(module, Linear):
            nn.init.kaiming_normal_(module.weight, mode='fan_out', nonlinearity='relu')
            if module.bias is not None:
                nn.init.constant_(module.bias, 0)
        elif isinstance(module, BatchNorm1d):
            nn.init.constant_(module.weight, 1)
            nn.init.constant_(module.bias, 0)
    
    def forward(self, x):
        # Feature extraction
        features = self.feature_extractor(x)
        
        # Simplified forward pass (no attention mechanism)
        output = self.classifier(features)
        
        return output

class UnifiedVarMaxModel(nn.Module):
    def __init__(self, input_sizes, hidden_size=128, num_classes_list=None, dropout_rate=0.3):
        """
        A single model that can handle multiple datasets with different input sizes
        and output classes by using dataset-specific adapters.
        
        Args:
            input_sizes: Dict of {dataset_name: input_size}
            hidden_size: Size of hidden layers
            num_classes_list: Dict of {dataset_name: num_classes}
            dropout_rate: Dropout rate
        """
        super(UnifiedVarMaxModel, self).__init__()
        
        self.dataset_names = list(input_sizes.keys())
        self.input_adapters = nn.ModuleDict()
        self.output_adapters = nn.ModuleDict()
        
        # Create input adapters for each dataset (to normalize input dimensions)
        for dataset_name, input_size in input_sizes.items():
            self.input_adapters[dataset_name] = nn.Sequential(
                BatchNorm1d(input_size),
                Linear(input_size, hidden_size * 2),
                nn.ReLU(),
                Dropout(dropout_rate)
            )
        
        # Shared feature extraction layers
        self.shared_feature_extractor = nn.Sequential(
            BatchNorm1d(hidden_size * 2),
            Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            Dropout(dropout_rate),
            BatchNorm1d(hidden_size)
        )
        
        # Create output adapters for each dataset (to handle different number of classes)
        for dataset_name, num_classes in num_classes_list.items():
            self.output_adapters[dataset_name] = nn.Sequential(
                Linear(hidden_size, hidden_size // 2),
                nn.ReLU(),
                Dropout(dropout_rate),
                BatchNorm1d(hidden_size // 2),
                Linear(hidden_size // 2, num_classes)
            )
        
        # Initialize weights
        self.apply(self._init_weights)
    
    def _init_weights(self, module):
        if isinstance(module, Linear):
            nn.init.kaiming_normal_(module.weight, mode='fan_out', nonlinearity='relu')
            if module.bias is not None:
                nn.init.constant_(module.bias, 0)
        elif isinstance(module, BatchNorm1d):
            nn.init.constant_(module.weight, 1)
            nn.init.constant_(module.bias, 0)
    
    def forward(self, x, dataset_name):
        # Apply dataset-specific input adapter
        x = self.input_adapters[dataset_name](x)
        
        # Apply shared feature extraction
        features = self.shared_feature_extractor(x)
        
        # Apply dataset-specific output adapter
        output = self.output_adapters[dataset_name](features)
        
        return output
    
    def get_features(self, x, dataset_name):
        """Extract features for anomaly detection"""
        x = self.input_adapters[dataset_name](x)
        features = self.shared_feature_extractor(x)
        return features

class MultiDatasetModel:
    def __init__(self, dataset_info, hidden_size=64, dropout_rate=0.3):
        self.models = {}
        self.dataset_info = dataset_info
        
        # Create a model for each dataset
        for dataset_name, info in dataset_info.items():
            self.models[dataset_name] = VarMaxModel(
                input_size=info['n_features'],
                hidden_size=hidden_size,
                num_classes=info['n_classes'],
                dropout_rate=dropout_rate
            )
    
    def to(self, device):
        """Move all models to the specified device"""
        for model in self.models.values():
            model.to(device)
        return self
    
    def train(self):
        """Set all models to training mode"""
        for model in self.models.values():
            model.train()
    
    def eval(self):
        """Set all models to evaluation mode"""
        for model in self.models.values():
            model.eval()
    
    def get_model(self, dataset_name):
        """Get the model for a specific dataset"""
        return self.models[dataset_name]
    
    def save_models(self, path):
        """Save all models"""
        for dataset_name, model in self.models.items():
            torch.save(model.state_dict(), f"{path}/varmax_model_{dataset_name}.pt")
    
    def load_models(self, path):
        """Load all models"""
        for dataset_name, model in self.models.items():
            model.load_state_dict(torch.load(f"{path}/varmax_model_{dataset_name}.pt"))
