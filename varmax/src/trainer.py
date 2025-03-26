import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import os
from datetime import datetime

class MultiDatasetTrainer:
    def __init__(self, model, dataloaders, device, learning_rate=0.001, weight_decay=0.01):
        self.model = model
        self.dataloaders = dataloaders
        self.device = device
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        
        # Create optimizers for each model
        self.optimizers = {}
        for dataset_name in dataloaders.keys():
            self.optimizers[dataset_name] = optim.Adam(
                self.model.get_model(dataset_name).parameters(),
                lr=learning_rate,
                weight_decay=weight_decay
            )
        
        # Create loss functions for each dataset
        self.criterion = nn.CrossEntropyLoss()
        
        # Create results directory
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
    
    def train_epoch(self, dataset_name):
        """Train one epoch for a specific dataset"""
        model = self.model.get_model(dataset_name)
        model.train()
        optimizer = self.optimizers[dataset_name]
        train_loader = self.dataloaders[dataset_name]['train']
        
        total_loss = 0
        all_preds = []
        all_labels = []
        
        for batch_idx, (data, target) in enumerate(tqdm(train_loader, desc=f"Training {dataset_name}")):
            data, target = data.to(self.device), target.to(self.device)
            
            optimizer.zero_grad()
            output = model(data)
            loss = self.criterion(output, target)
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Collect predictions and labels
            preds = output.argmax(dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(target.cpu().numpy())
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='weighted'
        )
        
        return {
            'loss': total_loss / len(train_loader),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def evaluate(self, dataset_name):
        """Evaluate model on a specific dataset"""
        model = self.model.get_model(dataset_name)
        model.eval()
        test_loader = self.dataloaders[dataset_name]['test']
        
        total_loss = 0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for data, target in tqdm(test_loader, desc=f"Evaluating {dataset_name}"):
                data, target = data.to(self.device), target.to(self.device)
                output = model(data)
                loss = self.criterion(output, target)
                
                total_loss += loss.item()
                
                # Collect predictions and labels
                preds = output.argmax(dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(target.cpu().numpy())
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='weighted'
        )
        
        return {
            'loss': total_loss / len(test_loader),
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def train(self, epochs, save_interval=5):
        """Train all models for specified number of epochs"""
        results = {}
        
        for epoch in range(1, epochs + 1):
            print(f"\nEpoch {epoch}/{epochs}")
            
            # Train and evaluate each dataset
            for dataset_name in self.dataloaders.keys():
                print(f"\nProcessing dataset: {dataset_name}")
                
                # Train
                train_metrics = self.train_epoch(dataset_name)
                
                # Evaluate
                eval_metrics = self.evaluate(dataset_name)
                
                # Store results
                if dataset_name not in results:
                    results[dataset_name] = {
                        'train': {metric: [] for metric in train_metrics.keys()},
                        'eval': {metric: [] for metric in eval_metrics.keys()}
                    }
                
                for metric in train_metrics:
                    results[dataset_name]['train'][metric].append(train_metrics[metric])
                    results[dataset_name]['eval'][metric].append(eval_metrics[metric])
                
                # Print metrics
                print(f"\n{dataset_name} Training Metrics:")
                for metric, value in train_metrics.items():
                    print(f"{metric}: {value:.4f}")
                
                print(f"\n{dataset_name} Evaluation Metrics:")
                for metric, value in eval_metrics.items():
                    print(f"{metric}: {value:.4f}")
            
            # Save models periodically
            if epoch % save_interval == 0:
                self.model.save_models("models")
                print(f"\nModels saved at epoch {epoch}")
        
        # Save final results
        self.save_results(results)
        return results
    
    def save_results(self, results):
        """Save training results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for dataset_name, dataset_results in results.items():
            # Save metrics to CSV
            metrics_file = os.path.join(self.results_dir, f"{dataset_name}_metrics_{timestamp}.csv")
            
            # Combine train and eval metrics
            metrics_df = pd.DataFrame()
            for phase in ['train', 'eval']:
                for metric, values in dataset_results[phase].items():
                    metrics_df[f"{phase}_{metric}"] = values
            
            metrics_df.to_csv(metrics_file, index=False)
            print(f"\nMetrics saved to {metrics_file}")
            
            # Save final evaluation metrics
            final_metrics = {
                metric: values[-1] 
                for metric, values in dataset_results['eval'].items()
            }
            
            metrics_file = os.path.join(self.results_dir, f"{dataset_name}_final_metrics_{timestamp}.txt")
            with open(metrics_file, 'w') as f:
                f.write(f"Final Evaluation Metrics for {dataset_name}:\n")
                for metric, value in final_metrics.items():
                    f.write(f"{metric}: {value:.4f}\n")
            
            print(f"Final metrics saved to {metrics_file}")
