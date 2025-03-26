import os
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='Run the Unified VARMAX System')
    parser.add_argument('--train', action='store_true', help='Train models first')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    
    # Create model directory if it doesn't exist
    if not os.path.exists('unified_model'):
        os.makedirs('unified_model', exist_ok=True)
        print("Created unified_model directory")
    
    # First create test models if needed
    if args.train or not os.path.exists('unified_model/dataset_stats.joblib'):
        print("Creating test models...")
        os.system('python create_test_model.py')
    
    # Run the server
    cmd = f'python unified_server.py --port {args.port}'
    if args.debug:
        cmd += ' --debug'
    
    print(f"Starting server with command: {cmd}")
    sys.exit(os.system(cmd))

if __name__ == "__main__":
    main() 