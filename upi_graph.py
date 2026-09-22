import json
import numpy as np
import torch


# --------------------------------------------------
# Paths
# --------------------------------------------------

MAPPING_PATH = "models/upi/upi_entity_mapping.json"


# --------------------------------------------------
# Load entity mapping
# --------------------------------------------------

with open(MAPPING_PATH, "r") as f:
    entity_mapping = json.load(f)


print("===== UPI GRAPH MAPPING =====")

print(
    "Mapping entries:",
    len(entity_mapping)
)


# --------------------------------------------------
# Inspect mapping
# --------------------------------------------------

first_items = list(entity_mapping.items())[:10]

print("\nFirst 10 mappings:")

for entity, node_id in first_items:

    print(
        entity,
        "->",
        node_id
    )


# --------------------------------------------------
# Convert feature vector into node feature
# --------------------------------------------------

def create_node_feature(transaction):

    feature_values = [

        transaction["amount"],
        transaction["hour_of_day"],
        transaction["is_weekend"],
        transaction["is_night_transaction"],
        transaction["time_since_last_txn_min"],
        transaction["user_avg_monthly_txn"],
        transaction["user_avg_txn_value"],
        transaction["user_loyalty_score"],
        transaction["new_device_flag"],
        transaction["ip_location_mismatch"],
        transaction["failed_attempts_last_24h"],
        transaction["transaction_velocity"],
        transaction["amount_deviation_score"],
        transaction["recurring_payment_flag"],
        transaction["balance_after_transaction"]

    ]

    features = np.array(
        feature_values,
        dtype=np.float32
    )

    return torch.tensor(
        features,
        dtype=torch.float32
    )


# --------------------------------------------------
# Test transaction
# --------------------------------------------------

test_transaction = {

    "amount": 1533.9,
    "hour_of_day": 0,
    "is_weekend": 0,
    "is_night_transaction": 1,
    "time_since_last_txn_min": 15409,
    "user_avg_monthly_txn": 36,
    "user_avg_txn_value": 472.44,
    "user_loyalty_score": 0.194,
    "new_device_flag": 0,
    "ip_location_mismatch": 0,
    "failed_attempts_last_24h": 2,
    "transaction_velocity": 0,
    "amount_deviation_score": 2.2467,
    "recurring_payment_flag": 1,
    "balance_after_transaction": 36024
}


node_feature = create_node_feature(
    test_transaction
)


print("\n===== NODE FEATURE TEST =====")

print(
    "Node feature shape:",
    node_feature.shape
)

print(
    "Expected:",
    "(15,)"
)

print(
    "NaN:",
    torch.isnan(node_feature).any().item()
)

print(
    "Inf:",
    torch.isinf(node_feature).any().item()
)

print("\n✅ NODE FEATURE CREATION WORKING")