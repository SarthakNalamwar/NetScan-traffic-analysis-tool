import os
import numpy as np
from src.data_collection import process_pcap
from src.feature_extraction import process_packet_data
from src.ml_model import NetworkTrafficClassifier, prepare_data

def main():
    # Get the path to the PCAP file
    pcap_file = input("Enter the path to the PCAP file: ").strip('"')
    
    print(f"Processing file: {pcap_file}")
    
    # Process the PCAP file
    packet_data = process_pcap(pcap_file)
    
    # Extract features
    X = process_packet_data(packet_data)
    
    # Load the trained model
    model_path = "models/rf_model.joblib"
    classifier = NetworkTrafficClassifier.load_model(model_path)
    
    # Make predictions
    predictions = classifier.predict(X)
    
    # Output predictions
    print(f"Predictions: {predictions}")

if __name__ == "__main__":
    main()
