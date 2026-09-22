import numpy as np


# Exact feature order used during UPI GNN training
GNN_FEATURE_COLUMNS = [
    "amount",
    "hour_of_day",
    "is_weekend",
    "is_night_transaction",
    "time_since_last_txn_min",
    "user_avg_monthly_txn",
    "user_avg_txn_value",
    "user_loyalty_score",
    "new_device_flag",
    "ip_location_mismatch",
    "failed_attempts_last_24h",
    "transaction_velocity",
    "amount_deviation_score",
    "recurring_payment_flag",
    "balance_after_transaction"
]


def prepare_gnn_features(transaction):
    """
    Convert one UPI transaction dictionary
    into the exact 15-feature NumPy array
    expected by the GNN.
    """

    values = []

    for column in GNN_FEATURE_COLUMNS:

        if column not in transaction:

            raise ValueError(
                f"Missing required UPI feature: {column}"
            )

        value = transaction[column]

        # Convert missing values to 0
        if value is None:

            value = 0.0

        values.append(float(value))

    features = np.array(
        values,
        dtype=np.float32
    )

    # Safety checks
    if np.isnan(features).any():

        raise ValueError(
            "UPI features contain NaN"
        )

    if np.isinf(features).any():

        raise ValueError(
            "UPI features contain Inf"
        )

    return features


if __name__ == "__main__":

    # Test transaction
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

    features = prepare_gnn_features(
        test_transaction
    )

    print("===== UPI FEATURE TEST =====")

    print(
        "Feature shape:",
        features.shape
    )

    print(
        "Expected shape:",
        "(15,)"
    )

    print(
        "NaN:",
        np.isnan(features).any()
    )

    print(
        "Inf:",
        np.isinf(features).any()
    )

    print("\nFeatures:")

    for name, value in zip(
        GNN_FEATURE_COLUMNS,
        features
    ):

        print(
            f"{name}: {value}"
        )

    print("\n✅ FEATURE PREPARATION WORKING")