import joblib
import os
from sklearn.ensemble import IsolationForest
import numpy as np

MODEL_PATH = "model.pkl"

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = IsolationForest(contamination=0.05)
    model.fit(np.random.rand(200,1))

def analyze_log(message):
    feature = [[len(message)]]
    prediction = model.predict(feature)
    return "High" if prediction[0] == -1 else "Low"
