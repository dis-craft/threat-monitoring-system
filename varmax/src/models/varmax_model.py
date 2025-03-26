import torch
import torch.nn as nn

class VARMAXModel(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, output_size):
        super(VARMAXModel, self).__init__()
        
        # Input normalization
        self.bn_input = nn.BatchNorm1d(input_size)
        
        # First layer
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.bn1 = nn.BatchNorm1d(hidden_size)
        
        # Second layer
        self.fc2 = nn.Linear(hidden_size, hidden_size // 2)  # 128 -> 64
        self.bn2 = nn.BatchNorm1d(hidden_size // 2)
        
        # Third layer
        self.fc3 = nn.Linear(hidden_size // 2, hidden_size // 4)  # 64 -> 32
        self.bn3 = nn.BatchNorm1d(hidden_size // 4)
        
        # Output layer
        self.fc4 = nn.Linear(hidden_size // 4, output_size)  # 32 -> 8
        
    def forward(self, x):
        # Input normalization
        x = self.bn_input(x)
        
        # First layer
        x = self.fc1(x)
        x = self.bn1(x)
        x = torch.relu(x)
        
        # Second layer
        x = self.fc2(x)
        x = self.bn2(x)
        x = torch.relu(x)
        
        # Third layer
        x = self.fc3(x)
        x = self.bn3(x)
        x = torch.relu(x)
        
        # Output layer
        x = self.fc4(x)
        x = torch.sigmoid(x)
        
        return x 