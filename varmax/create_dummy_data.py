import os
import pandas as pd
import numpy as np
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_dummy_data(num_samples=1000, num_features=20):
    """
    Create a dummy dataset for testing the VARMAX model
    """
    # Generate random features
    data = np.random.randn(num_samples, num_features)
    
    # Create a DataFrame with feature names
    columns = [f'feature_{i+1}' for i in range(num_features)]
    df = pd.DataFrame(data, columns=columns)
    
    # Save the dataset
    output_path = 'dummy_test_data.csv'
    df.to_csv(output_path, index=False)
    
    logger.info(f"Created dummy dataset with {num_samples} samples and {num_features} features")
    logger.info(f"Dataset saved to {output_path}")
    logger.info("You can use this file for testing the VARMAX model")

if __name__ == "__main__":
    create_dummy_data() 