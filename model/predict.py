import sys
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import types

# Import the required functions
from model.utils import numeric_features, COMMON_TLDS

# Create a mock module to satisfy joblib's requirements
mock_mp_main = types.ModuleType('__mp_main__')
mock_mp_main.get_url_values = lambda x: np.array(x) if not isinstance(x, pd.DataFrame) else x['url'].values
sys.modules['__mp_main__'] = mock_mp_main

MODEL_FILE = Path(__file__).resolve().parent / 'url_pipeline.joblib'

def safe_load_model():
    """Safely load the model with proper function definitions"""
    try:
        # First try normal loading
        return joblib.load(MODEL_FILE)
    except AttributeError as e:
        if "get_url_values" in str(e):
            print("Patching missing get_url_values function...")
            # Define the missing function in global scope
            def get_url_values(x):
                if isinstance(x, pd.DataFrame):
                    return x['url'].values
                return np.array(x)
            
            # Add to globals for joblib to find
            import __main__
            __main__.get_url_values = get_url_values
            
            # Try loading again
            return joblib.load(MODEL_FILE)
        else:
            raise

# Load model
if MODEL_FILE.exists():
    try:
        pipeline = safe_load_model()
        print("Model loaded successfully")
    except Exception as e:
        print(f"Error loading model: {e}")
        pipeline = None
else:
    pipeline = None
    print(f"WARNING: Model file not found at {MODEL_FILE}")

def predict_single(url):
    if pipeline is None:
        raise RuntimeError("Model not loaded. Please train the model first.")
    
    df = pd.DataFrame({'url': [url]})
    pred = pipeline.predict(df)
    prob = None
    
    # Get the classifier from the pipeline
    clf = pipeline.named_steps.get('clf', None)
    if clf is None:
        # If no 'clf' step, try to find the classifier directly
        for step_name, step in pipeline.named_steps.items():
            if hasattr(step, 'predict_proba') or hasattr(step, 'decision_function'):
                clf = step
                break
    
    if clf is not None:
        if hasattr(clf, 'predict_proba'):
            prob = pipeline.predict_proba(df)[0][1]
        elif hasattr(clf, 'decision_function'):
            dfv = pipeline.decision_function(df)[0]
            prob = 1 / (1 + 2.71828 ** (-dfv/4.0))
    
    label = "malicious" if pred[0] == 1 else "benign"
    return label, prob

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python model/predict.py <url1> [url2] ...")
        sys.exit(0)
    for u in sys.argv[1:]:
        label, prob = predict_single(u)
        if prob is not None:
            print(f"{u} -> {label} (score={prob:.4f})")
        else:
            print(f"{u} -> {label}")