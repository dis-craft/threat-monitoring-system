import os
import torch
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score, confusion_matrix, classification_report
)
from sklearn.metrics import ConfusionMatrixDisplay
from tqdm import tqdm

class UnifiedEvaluator:
    def __init__(self, model, dataloaders, device="cpu", results_dir="results"):
        """
        Evaluator for unified model across multiple datasets
        
        Args:
            model: UnifiedVarMaxModel instance
            dataloaders: Dict of {dataset_name: {'test': test_loader}}
            device: Device to evaluate on
            results_dir: Directory to save results
        """
        self.model = model.to(device)
        self.dataloaders = dataloaders
        self.device = device
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)
    
    def evaluate_all_datasets(self):
        """Evaluate the unified model on all datasets and return metrics"""
        self.model.eval()
        all_metrics = {}
        
        for dataset_name, loaders in self.dataloaders.items():
            print(f"\n📊 Evaluating {dataset_name} dataset:")
            metrics = self.evaluate_dataset(dataset_name, loaders['test'])
            all_metrics[dataset_name] = metrics
            
        # Calculate average metrics across all datasets
        avg_metrics = {
            'Accuracy': np.mean([m['Accuracy'] for m in all_metrics.values()]),
            'F1 Score': np.mean([m['F1 Score'] for m in all_metrics.values()]),
            'Precision': np.mean([m['Precision'] for m in all_metrics.values()]),
            'Recall': np.mean([m['Recall'] for m in all_metrics.values()])
        }
        
        print("\n📊 Overall metrics across all datasets:")
        for metric_name, metric_value in avg_metrics.items():
            print(f"{metric_name}: {metric_value:.4f}")
            
        return all_metrics, avg_metrics
    
    def evaluate_dataset(self, dataset_name, test_loader):
        """Evaluate the unified model on a specific dataset and return metrics"""
        all_labels = []
        all_predictions = []
        
        with torch.no_grad():
            for inputs, labels in tqdm(test_loader, desc=f"Evaluating {dataset_name}"):
                inputs, labels = inputs.to(self.device), labels.to(self.device)
                logits = self.model(inputs, dataset_name)
                predictions = logits.argmax(dim=1).cpu().numpy()
                all_predictions.extend(predictions)
                all_labels.extend(labels.cpu().numpy())
        
        metrics = {
            'Accuracy': accuracy_score(all_labels, all_predictions),
            'F1 Score': f1_score(all_labels, all_predictions, average='weighted', zero_division=1),
            'Precision': precision_score(all_labels, all_predictions, average='weighted', zero_division=1),
            'Recall': recall_score(all_labels, all_predictions, average='weighted', zero_division=1)
        }
        
        # Print metrics to console
        print(f"\nEvaluation Metrics for {dataset_name}:")
        for metric_name, metric_value in metrics.items():
            print(f"{metric_name}: {metric_value:.4f}")
        
        # Plot metrics as a bar chart
        plt.figure(figsize=(8, 5))
        plt.bar(metrics.keys(), metrics.values(), color=['skyblue', 'salmon', 'limegreen', 'orange'])
        plt.title(f'{dataset_name} - Metrics')
        plt.ylabel('Score')
        plt.ylim(0, 1.0)  # Set y-axis from 0 to 1 for better comparison
        plt.tight_layout()
        metrics_path = os.path.join(self.results_dir, f'{dataset_name}_unified_metrics.png')
        plt.savefig(metrics_path)
        plt.close()
        print(f"Metrics visualization saved as '{os.path.abspath(metrics_path)}'")
        
        # Generate confusion matrix
        unique_labels = np.unique(all_labels)
        cm = confusion_matrix(all_labels, all_predictions, labels=unique_labels)
        
        # Create class names (simple numeric if we don't have label encoders)
        class_names = [f"Class {i}" for i in unique_labels]
        
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=class_names, yticklabels=class_names)
        plt.title(f'Confusion Matrix ({dataset_name})', fontsize=16)
        plt.xlabel('Predicted Label', fontsize=14)
        plt.ylabel('True Label', fontsize=14)
        plt.xticks(rotation=45, ha='right', fontsize=10)
        plt.yticks(rotation=45, va='center', fontsize=10)
        plt.tight_layout()
        cm_path = os.path.join(self.results_dir, f'unified_confusion_matrix_{dataset_name}.png')
        plt.savefig(cm_path, dpi=300)
        plt.close()
        print(f"Confusion matrix saved as '{os.path.abspath(cm_path)}'")
        
        return metrics 