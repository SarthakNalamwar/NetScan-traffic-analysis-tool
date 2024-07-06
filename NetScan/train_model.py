import os
import numpy as np
from src.data_collection import process_pcap
from src.feature_extraction import process_packet_data
from src.ml_model import NetworkTrafficClassifier, prepare_data

def load_and_process_data(data_dir):
    features = []
    labels = []

    for filename in os.listdir(data_dir):
        if filename.endswith(('.pcap','pcapng')):
            file_path = os.path.join(data_dir, filename)
            print(f"Processing {file_path}...")
            
            # Determine if it's an attack file based on filename
            is_attack = 'attack' in filename.lower()
            
            # Process PCAP file
            packet_data = process_pcap(file_path)
            
            # Extract features
            file_features = process_packet_data(packet_data)
            
            features.append(file_features)
            labels.append(np.full(file_features.shape[0], int(is_attack)))

    return np.vstack(features), np.concatenate(labels)

def main():
    # Directory containing your PCAP files
    data_dir = input("Enter the path to the directory containing PCAP files: ")

    print("Loading and processing data...")
    X, y = load_and_process_data(data_dir)
    
    print(f"Loaded data shape: {X.shape}")
    print(f"Number of attack samples: {np.sum(y)}")
    print(f"Number of normal samples: {len(y) - np.sum(y)}")

    # Prepare data
    X, y = prepare_data(X, y)

    # Create and train the model
    classifier = NetworkTrafficClassifier()
    print("Training model...")
    accuracy, report = classifier.train(X, y)

    print(f"\nModel accuracy: {accuracy}")

    # Save the model
    model_path = "models/rf_model.joblib"
    classifier.save_model(model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    main()