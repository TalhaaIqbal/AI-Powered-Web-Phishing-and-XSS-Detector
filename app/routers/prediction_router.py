from ..services.prediction_service import PredictionService
from fastapi import APIRouter, HTTPException


router = APIRouter(prefix="/prediction", tags=["Prediction"])

@router.post("/predict_xss", response_model=dict)
def predict_xss(user_input: str):
    if not user_input:
        raise HTTPException(status_code=400, detail="User input is required")
    else:
        try:
            pred = PredictionService().predict_xss(user_input)
            if hasattr(pred, 'item'):
                pred = pred.item()
            return {"prediction": int(pred)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))



@router.post("/predict_phishing_url", response_model=dict)
def predict_phishing_url(user_input: str):
    if not user_input:
        raise HTTPException(status_code=400, detail="User input is required")
    else:
        try:
            pred = PredictionService().predict_phishing_url(user_input)
            # Convert numpy types to Python native types for JSON serialization
            if isinstance(pred, dict):
                return {k: int(v.item()) if hasattr(v, 'item') else v for k, v in pred.items()}
            elif hasattr(pred, 'item'):
                return {"prediction": int(pred.item())}
            return {"prediction": pred}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))