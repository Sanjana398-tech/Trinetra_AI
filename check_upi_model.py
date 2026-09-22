import os
import json
import torch
import xgboost as xgb

MODEL_DIR = os.path.join("models", "upi")

print("===== UPI MODEL CHECK =====")

# Check files
required_files = [
    "upi_gnn.pth",
    "upi_xgboost.json",
    "model_info.json",
    "upi_inference_config.json",
    "upi_entity_mapping.json"
]

for filename in required_files:
    path = os.path.join(MODEL_DIR, filename)

    if os.path.exists(path):
        print(f"{filename} → FOUND ✅")
    else:
        print(f"{filename} → MISSING ❌")


# Environment
print("\n===== ENVIRONMENT =====")

print("PyTorch:", torch.__version__)
print("CUDA available:", torch.cuda.is_available())

if torch.cuda.is_available():
    print("GPU:", torch.cuda.get_device_name(0))

print("XGBoost:", xgb.__version__)


# Model info
print("\n===== MODEL INFO =====")

with open(
    os.path.join(MODEL_DIR, "model_info.json"),
    "r"
) as f:
    model_info = json.load(f)

print(json.dumps(model_info, indent=4))


# XGBoost
print("\n===== LOADING XGBOOST =====")

loaded_xgb = xgb.XGBClassifier()

loaded_xgb.load_model(
    os.path.join(
        MODEL_DIR,
        "upi_xgboost.json"
    )
)

print("XGBoost loaded successfully ✅")

print(
    "XGBoost features:",
    loaded_xgb.n_features_in_
)

print(
    "Expected features:",
    model_info["total_xgboost_features"]
)

if (
    loaded_xgb.n_features_in_
    == model_info["total_xgboost_features"]
):
    print("Feature count matches ✅")
else:
    print("Feature count mismatch ❌")


print("\n================================")
print("✅ UPI MODEL CHECK COMPLETE")
print("================================")