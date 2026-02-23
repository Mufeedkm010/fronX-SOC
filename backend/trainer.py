import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_PATH = "model.pkl"

def train_model():
    dataset_path = "../logs/sample_logs.csv"

    if not os.path.exists(dataset_path):
        print("Dataset not found!")
        return

    data = pd.read_csv(dataset_path)

    lengths = data['message'].apply(len).values.reshape(-1,1)

    model = IsolationForest(contamination=0.05)
    model.fit(lengths)

    joblib.dump(model, MODEL_PATH)

    print("Model trained successfully!")
    
if __name__ == "__main__":
    train_model()
