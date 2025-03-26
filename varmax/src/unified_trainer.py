import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import ReduceLROnPlateau
import numpy as np
import matplotlib.pyplot as plt
import os
from tqdm import tqdm
import random
from sklearn.utils.class_weight import compute_class_weight

class UnifiedModelTrainer:
    def __init__(self, model, dataloaders, device, learning_rate=0.001, weight_decay=0.01):
        """
        Trainer for the unified model that can handle multiple datasets

        Args:
            model: The UnifiedVarMaxModel instance
            dataloaders: Dict of {dataset_name: {'train': train_loader, 'val': val_loader, 'test': test_loader}}
            device: Device to train on
            learning_rate: Learning rate for optimizer
            weight_decay: Weight decay for regularization
        """
        self.model = model
        self.dataloaders = dataloaders
        self.device = device
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        
        # Setup optimizer
        self.optimizer = optim.Adam(
            self.model.parameters(), 
            lr=learning_rate, 
            weight_decay=weight_decay
        )
        
        # Learning rate scheduler
        self.scheduler = ReduceLROnPlateau(
            self.optimizer, 
            mode='min', 
            factor=0.5, 
            patience=5, 
            verbose=True
        )
        
        # Calculate class weights for each dataset
        self.class_weights = {}
        for dataset_name, loaders in dataloaders.items():
            # Extract all labels from training set
            all_labels = []
            for _, labels in loaders['train']:
                all_labels.extend(labels.numpy())
                
            unique_labels = np.unique(all_labels)
            class_weights = compute_class_weight(
                class_weight='balanced',
                classes=unique_labels,
                y=all_labels
            )
            self.class_weights[dataset_name] = torch.tensor(
                class_weights, 
                dtype=torch.float32, 
                device=device
            )
            
        # Setup results directory
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        
    def train(self, epochs=10, patience=10):
        """
        Train the unified model on all datasets
        
        Args:
            epochs: Number of epochs
            patience: Patience for early stopping
        
        Returns:
            Dictionary of training history
        """
        history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }
        
        # Initialize tracking variables for early stopping
        best_val_loss = float('inf')
        no_improve_epochs = 0
        
        print(f"\n🚀 Starting unified model training for {epochs} epochs")
        
        for epoch in range(epochs):
            # Training phase
            self.model.train()
            train_losses = []
            train_accuracies = []
            
            # Create a list of all dataset batches
            all_dataset_batches = []
            for dataset_name, loaders in self.dataloaders.items():
                for features, labels in loaders['train']:
                    all_dataset_batches.append((dataset_name, features, labels))
            
            # Shuffle the batches to mix datasets during training
            random.shuffle(all_dataset_batches)
            
            # Train on all batches
            train_pbar = tqdm(all_dataset_batches, desc=f"Epoch {epoch+1}/{epochs} [Train]")
            for dataset_name, features, labels in train_pbar:
                features, labels = features.to(self.device), labels.to(self.device)
                
                # Clear gradients
                self.optimizer.zero_grad()
                
                # Forward pass
                outputs = self.model(features, dataset_name)
                
                # Calculate loss with class weights
                criterion = nn.CrossEntropyLoss(weight=self.class_weights[dataset_name])
                loss = criterion(outputs, labels)
                
                # Backward pass and optimization
                loss.backward()
                self.optimizer.step()
                
                # Calculate accuracy
                _, predicted = torch.max(outputs.data, 1)
                total = labels.size(0)
                correct = (predicted == labels).sum().item()
                accuracy = 100 * correct / total
                
                # Update progress bar
                train_pbar.set_postfix({'loss': f"{loss.item():.4f}", 'acc': f"{accuracy:.2f}%"})
                
                # Record metrics
                train_losses.append(loss.item())
                train_accuracies.append(accuracy)
            
            # Calculate average metrics for this epoch
            avg_train_loss = np.mean(train_losses)
            avg_train_acc = np.mean(train_accuracies)
            
            # Validation phase
            self.model.eval()
            val_losses = []
            val_accuracies = []
            
            with torch.no_grad():
                for dataset_name, loaders in self.dataloaders.items():
                    val_loader = loaders['val']
                    criterion = nn.CrossEntropyLoss(weight=self.class_weights[dataset_name])
                    
                    for features, labels in val_loader:
                        features, labels = features.to(self.device), labels.to(self.device)
                        
                        # Forward pass
                        outputs = self.model(features, dataset_name)
                        
                        # Calculate loss
                        loss = criterion(outputs, labels)
                        
                        # Calculate accuracy
                        _, predicted = torch.max(outputs.data, 1)
                        total = labels.size(0)
                        correct = (predicted == labels).sum().item()
                        accuracy = 100 * correct / total
                        
                        # Record metrics
                        val_losses.append(loss.item())
                        val_accuracies.append(accuracy)
            
            # Calculate average metrics
            avg_val_loss = np.mean(val_losses)
            avg_val_acc = np.mean(val_accuracies)
            
            # Update learning rate
            self.scheduler.step(avg_val_loss)
            
            # Update history
            history['train_loss'].append(avg_train_loss)
            history['val_loss'].append(avg_val_loss)
            history['train_acc'].append(avg_train_acc)
            history['val_acc'].append(avg_val_acc)
            
            # Print epoch summary
            print(f"Epoch {epoch+1}/{epochs}:")
            print(f"Train Loss: {avg_train_loss:.4f}, Train Accuracy: {avg_train_acc:.2f}%")
            print(f"Val Loss: {avg_val_loss:.4f}, Val Accuracy: {avg_val_acc:.2f}%")
            
            # Early stopping
            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                no_improve_epochs = 0
                # Save best model
                torch.save(self.model.state_dict(), os.path.join(self.results_dir, "unified_varmax_best.pt"))
                print("✅ Saved new best model!")
            else:
                no_improve_epochs += 1
                print(f"⚠️ No improvement for {no_improve_epochs} epochs")
                
            if no_improve_epochs >= patience:
                print(f"🛑 Early stopping triggered after {epoch+1} epochs")
                break
                
        # Plot and save training curves
        self._plot_learning_curves(history)
        
        # Load best model
        self.model.load_state_dict(torch.load(os.path.join(self.results_dir, "unified_varmax_best.pt")))
        
        return history
    
    def _plot_learning_curves(self, history):
        """Plot and save learning curves"""
        plt.figure(figsize=(12, 5))
        
        # Plot loss
        plt.subplot(1, 2, 1)
        plt.plot(history['train_loss'], label='Train Loss')
        plt.plot(history['val_loss'], label='Validation Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.title('Training and Validation Loss')
        plt.legend()
        
        # Plot accuracy
        plt.subplot(1, 2, 2)
        plt.plot(history['train_acc'], label='Train Accuracy')
        plt.plot(history['val_acc'], label='Validation Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy (%)')
        plt.title('Training and Validation Accuracy')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, "unified_model_learning_curves.png"))
        plt.close() 