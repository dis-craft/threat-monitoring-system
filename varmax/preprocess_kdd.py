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
            
            print(f"Converted labels. Value counts:\n{df['label'].value_counts()}")
            
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