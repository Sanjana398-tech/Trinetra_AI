import pandas as pd

from backend.utils.url_features import extract_url_features
from backend.utils.xgboost_loader import predict_url


# ==========================================
# TEST URL
# ==========================================

test_url = "https://secure-login-account-verification.example.com/login"


print("================================")
print("STEP 12.12 - XGBOOST URL TEST")
print("================================")

print("\nTest URL:")
print(test_url)


# ==========================================
# EXTRACT FEATURES
# ==========================================

features = extract_url_features(test_url)

print("\nFeatures extracted:")
print(len(features))


# ==========================================
# CONVERT TO DATAFRAME
# ==========================================

feature_df = pd.DataFrame([features])


# ==========================================
# PREDICTION
# ==========================================

result = predict_url(feature_df)


print("\n================================")
print("PREDICTION RESULT")
print("================================")

print(result)