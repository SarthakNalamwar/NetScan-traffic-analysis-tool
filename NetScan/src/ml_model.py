import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from typing import Tuple

class NetworkTrafficClassifier:
    def __init__(self, n_estimators=100, random_state=42):
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)

    def train(self, X: np.ndarray, y: np.ndarray) -> Tuple[float, dict]:
        """
        Train the model on the given data.
        
        :param X: Feature matrix
        :param y: Target vector (0 for normal, 1 for attack/vulnerability)
        :return: Tuple of (accuracy, classification_report)
        """
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        accuracy = self.model.score(X_test, y_test)
        
        report = classification_report(y_test, y_pred, output_dict=True)
        
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return accuracy, report

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Make predictions on the given data.
        
        :param X: Feature matrix
        :return: Predicted labels (0 for normal, 1 for attack/vulnerability)
        """
        return self.model.predict(X)

    def save_model(self, filename: str):
        """Save the trained model to a file."""
        joblib.dump(self.model, filename)

    @classmethod
    def load_model(cls, filename: str):
        """Load a trained model from a file."""
        classifier = cls()
        classifier.model = joblib.load(filename)
        return classifier

def prepare_data(feature_matrix: np.ndarray, labels: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """
    Prepare the data for training/prediction.
    This function can be expanded to include more preprocessing steps.
    
    :param feature_matrix: The feature matrix from feature_extraction.py
    :param labels: The corresponding labels (0 for normal, 1 for attack/vulnerability)
    :return: Preprocessed feature matrix and labels
    """
    # For now, we'll just ensure the types are correct
    return feature_matrix.astype(np.float32), labels.astype(np.int32)

if __name__ == "__main__":
    # Example usage
    # This would typically be replaced with your actual data
    X = np.random.rand(1000, 8)  # 1000 samples, 8 features
    y = np.random.randint(0, 2, 1000)  # Binary classification
    
    X, y = prepare_data(X, y)
    
    classifier = NetworkTrafficClassifier()
    accuracy, report = classifier.train(X, y)
    
    print(f"\nModel accuracy: {accuracy}")
    
    # Save the model
    classifier.save_model("../models/rf_model.joblib")
    
    # Load the model (just as an example)
    loaded_classifier = NetworkTrafficClassifier.load_model("../models/rf_model.joblib")
    
    # Make predictions
    sample_data = np.random.rand(10, 8)  # 10 samples for prediction
    predictions = loaded_classifier.predict(sample_data)
    print("\nSample predictions:", predictions)