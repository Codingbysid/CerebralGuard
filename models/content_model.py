"""
Custom BERT-based Phishing Detection Model for CerebralGuard
Provides independent ML analysis to complement Gemini API calls.
"""

import torch
import torch.nn as nn
from transformers import BertTokenizer, BertForSequenceClassification, BertConfig
from torch.utils.data import Dataset, DataLoader
import numpy as np
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import json
import os
from dotenv import load_dotenv
from loguru import logger
import pickle

# Load environment variables
load_dotenv()

class PhishingDataset(Dataset):
    """Custom dataset for phishing email classification."""
    
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 512):
        """
        Initialize the dataset.
        
        Args:
            texts: List of email texts
            labels: List of labels (0 for legitimate, 1 for phishing)
            tokenizer: BERT tokenizer
            max_length: Maximum sequence length
        """
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]
        
        # Tokenize the text
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

class PhishingBERTModel(nn.Module):
    """Custom BERT model for phishing detection."""
    
    def __init__(self, model_name: str = 'bert-base-uncased', num_labels: int = 2):
        """
        Initialize the BERT model for sequence classification.
        
        Args:
            model_name: Pre-trained BERT model name
            num_labels: Number of classification labels (2 for binary)
        """
        super(PhishingBERTModel, self).__init__()
        
        # Load pre-trained BERT configuration
        self.config = BertConfig.from_pretrained(model_name)
        self.config.num_labels = num_labels
        
        # Load pre-trained BERT model
        self.bert = BertForSequenceClassification.from_pretrained(
            model_name, 
            config=self.config
        )
        
        # Add dropout for regularization
        self.dropout = nn.Dropout(0.1)
        
        # Add a classification head
        self.classifier = nn.Linear(self.config.hidden_size, num_labels)
    
    def forward(self, input_ids, attention_mask, labels=None):
        """
        Forward pass through the model.
        
        Args:
            input_ids: Token IDs
            attention_mask: Attention mask
            labels: Ground truth labels (optional)
            
        Returns:
            Model outputs with loss (if labels provided)
        """
        # Get BERT outputs
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels
        )
        
        return outputs

class PhishingDetector:
    """Main class for phishing detection using fine-tuned BERT."""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the phishing detector.
        
        Args:
            model_path: Path to saved model (if None, will load default)
        """
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = None
        self.tokenizer = None
        self.model_path = model_path or os.getenv('MODEL_SAVE_PATH', './models/saved/')
        
        # Create model directory if it doesn't exist
        Path(self.model_path).mkdir(parents=True, exist_ok=True)
        
        self._load_model()
    
    def _load_model(self):
        """Load the BERT model and tokenizer."""
        try:
            # First try to load the trained CerebralGuard model
            cerebralguard_model_path = Path(self.model_path) / 'cerebralguard_model'
            if cerebralguard_model_path.exists():
                # Load the trained BERT model and tokenizer
                self.tokenizer = BertTokenizer.from_pretrained(str(cerebralguard_model_path))
                self.model = BertForSequenceClassification.from_pretrained(str(cerebralguard_model_path))
                
                # Load training metrics
                metrics_file = cerebralguard_model_path / 'training_metrics.json'
                if metrics_file.exists():
                    with open(metrics_file, 'r') as f:
                        self.training_metrics = json.load(f)
                        accuracy = self.training_metrics['test_metrics']['accuracy']
                        logger.info(f"Loaded trained CerebralGuard BERT model (accuracy: {accuracy:.1%})")
                else:
                    logger.info("Loaded trained CerebralGuard BERT model")
                
                self.model.to(self.device)
                self.model.eval()
                return
            
            # Fallback to legacy model loading
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            self.model = PhishingBERTModel()
            
            # Load saved weights if available
            model_file = Path(self.model_path) / 'phishing_bert_model.pth'
            if model_file.exists():
                self.model.load_state_dict(torch.load(model_file, map_location=self.device))
                logger.info("Loaded legacy phishing detection model")
            else:
                logger.info("No pre-trained model found. Using untrained model.")
            
            self.model.to(self.device)
            self.model.eval()
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            # Final fallback to basic initialization
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            self.model = PhishingBERTModel()
            self.model.to(self.device)
    
    def preprocess_email(self, email_text: str) -> str:
        """
        Preprocess email text for model input.
        
        Args:
            email_text: Raw email text
            
        Returns:
            Preprocessed text
        """
        # Basic preprocessing
        text = email_text.lower().strip()
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        # Truncate if too long (BERT has 512 token limit)
        if len(text) > 2000:  # Rough estimate
            text = text[:2000]
        
        return text
    
    def predict(self, email_text: str) -> Dict[str, float]:
        """
        Predict phishing probability for an email.
        
        Args:
            email_text: Email text to analyze
            
        Returns:
            Dictionary with prediction confidence and probability
        """
        if self.model is None:
            logger.error("Model not loaded")
            return {'confidence': 0.0, 'phishing_probability': 0.5}
        
        try:
            # Preprocess text
            processed_text = self.preprocess_email(email_text)
            
            # Tokenize
            inputs = self.tokenizer(
                processed_text,
                truncation=True,
                padding='max_length',
                max_length=512,
                return_tensors='pt'
            )
            
            # Move to device
            input_ids = inputs['input_ids'].to(self.device)
            attention_mask = inputs['attention_mask'].to(self.device)
            
            # Get prediction
            with torch.no_grad():
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                
                # Get phishing probability (class 1)
                phishing_prob = probabilities[0][1].item()
                
                # Calculate confidence (distance from 0.5)
                confidence = abs(phishing_prob - 0.5) * 2
                
                return {
                    'confidence': confidence,
                    'phishing_probability': phishing_prob,
                    'prediction': 'phishing' if phishing_prob > 0.5 else 'legitimate'
                }
                
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return {'confidence': 0.0, 'phishing_probability': 0.5}
    
    def train(self, training_data: List[Dict], validation_data: List[Dict] = None, 
              epochs: int = 3, batch_size: int = 16, learning_rate: float = 2e-5):
        """
        Train the phishing detection model.
        
        Args:
            training_data: List of dictionaries with 'text' and 'label' keys
            validation_data: Optional validation data
            epochs: Number of training epochs
            batch_size: Batch size for training
            learning_rate: Learning rate for optimizer
        """
        if self.model is None:
            logger.error("Model not initialized")
            return
        
        try:
            # Prepare data
            train_texts = [item['text'] for item in training_data]
            train_labels = [item['label'] for item in training_data]
            
            # Create dataset
            train_dataset = PhishingDataset(train_texts, train_labels, self.tokenizer)
            train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
            
            # Setup training
            optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)
            criterion = nn.CrossEntropyLoss()
            
            # Training loop
            self.model.train()
            for epoch in range(epochs):
                total_loss = 0
                for batch in train_loader:
                    # Move to device
                    input_ids = batch['input_ids'].to(self.device)
                    attention_mask = batch['attention_mask'].to(self.device)
                    labels = batch['labels'].to(self.device)
                    
                    # Forward pass
                    outputs = self.model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                    loss = outputs.loss
                    
                    # Backward pass
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(train_loader)
                logger.info(f"Epoch {epoch + 1}/{epochs}, Average Loss: {avg_loss:.4f}")
            
            # Save model
            self.save_model()
            logger.info("Training completed and model saved")
            
        except Exception as e:
            logger.error(f"Error during training: {e}")
    
    def save_model(self):
        """Save the trained model."""
        try:
            model_file = Path(self.model_path) / 'phishing_bert_model.pth'
            torch.save(self.model.state_dict(), model_file)
            logger.info(f"Model saved to {model_file}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def generate_synthetic_data(self, num_samples: int = 1000) -> List[Dict]:
        """
        Generate synthetic training data using Gemini API.
        This is an advanced technique for data augmentation.
        
        Args:
            num_samples: Number of synthetic samples to generate
            
        Returns:
            List of synthetic training examples
        """
        # This would integrate with Gemini API to generate synthetic phishing emails
        # For now, return a placeholder structure
        synthetic_data = []
        
        # Example synthetic data structure
        for i in range(num_samples):
            synthetic_data.append({
                'text': f"Synthetic phishing email {i}",
                'label': 1 if i % 2 == 0 else 0  # Alternating for demo
            })
        
        logger.info(f"Generated {len(synthetic_data)} synthetic training examples")
        return synthetic_data

# Global instance for easy access
phishing_detector = PhishingDetector() 