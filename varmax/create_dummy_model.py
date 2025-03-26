import os
import torch
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Model definition (same as in server.py)
class VARMAXModel(torch.nn.Module):
    def __init__(self, input_size=20, hidden_size=128, output_size=8):
        super(VARMAXModel, self).__init__()
        self.bn_input = torch.nn.BatchNorm1d(input_size)
        self.fc1 = torch.nn.Linear(input_size, hidden_size)
        self.bn1 = torch.nn.BatchNorm1d(hidden_size)
        self.fc2 = torch.nn.Linear(hidden_size, hidden_size // 2)
        self.bn2 = torch.nn.BatchNorm1d(hidden_size // 2)
        self.fc3 = torch.nn.Linear(hidden_size // 2, hidden_size // 4)
        self.bn3 = torch.nn.BatchNorm1d(hidden_size // 4)
        self.fc4 = torch.nn.Linear(hidden_size // 4, output_size)
        self.relu = torch.nn.ReLU()
        self.dropout = torch.nn.Dropout(0.2)
        
    def forward(self, x):
        x = self.bn_input(x)
        x = self.fc1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.dropout(x)
        
        x = self.fc2(x)
        x = self.bn2(x)
        x = self.relu(x)
        x = self.dropout(x)
        
        x = self.fc3(x)
        x = self.bn3(x)
        x = self.relu(x)
        x = self.dropout(x)
        
        x = self.fc4(x)
        return x

def create_dummy_model():
    # Create a model with the same architecture
    model = VARMAXModel(input_size=20, hidden_size=128, output_size=8)
    
    # Save the model to the models directory
    model_path = os.path.join('models', 'varmax_model.pt')
    torch.save(model.state_dict(), model_path)
    
    logger.info(f"Dummy model saved to {model_path}")
    logger.info("You can now run server.py to use this model for testing")

if __name__ == "__main__":
    create_dummy_model() 