 
# src/data_preprocessing.py
from sklearn.preprocessing import StandardScaler

def normalize_features(features):
    scaler = StandardScaler()
    return scaler.fit_transform(features)
