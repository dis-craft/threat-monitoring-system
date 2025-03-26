import joblib
import os
import numpy as np

try:
    print("Starting test save script...")
    
    # Create a simple model (just an array)
    model = np.array([1, 2, 3, 4, 5])
    
    # Define the path
    model_path = 'data/trained_models/test_model.pkl'
    
    # Make sure directory exists
    print(f"Checking if directory exists: {os.path.dirname(model_path)}")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save the model
    print(f"Saving model to: {model_path}")
    joblib.dump(model, model_path)
    
    # Verify file exists
    if os.path.exists(model_path):
        print(f"Successfully saved file at: {model_path}")
    else:
        print(f"File not found at: {model_path}")
    
    print("Done!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc() 