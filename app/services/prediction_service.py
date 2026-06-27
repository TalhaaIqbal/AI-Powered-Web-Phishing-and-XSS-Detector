import joblib
import numpy as np
from ..ml.training_files.phishing_feature_extractor import PhishingFeatureExtractor

class PredictionService:
    def __init__(self):
        self.xss_model = joblib.load("app/ml/artifacts/xss_model.pkl")
        self.xss_vectorizer = joblib.load("app/ml/artifacts/xss_vectorizer.pkl")
        self.random_forest_model = joblib.load("app/ml/artifacts/random_forest_model.pkl")
        self.xgboost_model = joblib.load("app/ml/artifacts/xgboost_model.pkl")

    def predict_xss(self, user_input: str):
        vect = self.xss_vectorizer.transform([user_input])
        prediction = self.xss_model.predict(vect)[0]
        return prediction
    
    def predict_phishing_url(self, user_input: str):
        extractor = PhishingFeatureExtractor(user_input)
        features = extractor.get_features_array()
        
        forest_pred = self.random_forest_model.predict(np.array(features).reshape(1, -1))
        xgboost_pred = self.xgboost_model.predict(np.array(features).reshape(1, -1))

        forest_proba = self.random_forest_model.predict_proba(np.array(features).reshape(1, -1))
        forest_confidence = float(max(forest_proba[0]))
        
        xgboost_proba = self.xgboost_model.predict_proba(np.array(features).reshape(1, -1))
        xgboost_confidence = float(max(xgboost_proba[0]))

        forest_verdict = "malicious" if int(forest_pred[0]) == 0 else "safe"
        xgboost_verdict = "malicious" if int(xgboost_pred[0]) == 0 else "safe"

        return {
            "forest_prediction": forest_pred,
            "forest_confidence": forest_confidence,
            "forest_verdict": forest_verdict,
            "xgboost_prediction": xgboost_pred,
            "xgboost_confidence": xgboost_confidence,
            "xgboost_verdict": xgboost_verdict
        }