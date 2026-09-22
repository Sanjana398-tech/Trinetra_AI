import os
import json
import hashlib
import re
from datetime import datetime
from urllib.parse import parse_qs, urlparse
import torch
import numpy as np
import xgboost as xgb
from torch_geometric.data import Data

from upi_gnn_model import UPI_GNN
from upi_features import GNN_FEATURE_COLUMNS, prepare_gnn_features


class UPIDetector:

    def __init__(self):

        # -----------------------------
        # Paths
        # -----------------------------

        self.model_dir = os.path.join(
            os.path.dirname(__file__),
            "models",
            "upi"
        )

        # -----------------------------
        # Device
        # -----------------------------

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        # -----------------------------
        # Load model information
        # -----------------------------

        with open(
            os.path.join(
                self.model_dir,
                "model_info.json"
            ),
            "r"
        ) as f:

            self.model_info = json.load(f)

        # -----------------------------
        # Load inference configuration
        # -----------------------------

        with open(
            os.path.join(
                self.model_dir,
                "upi_inference_config.json"
            ),
            "r"
        ) as f:

            self.config = json.load(f)

        # -----------------------------
        # Load entity mapping
        # -----------------------------

        with open(
            os.path.join(
                self.model_dir,
                "upi_entity_mapping.json"
            ),
            "r"
        ) as f:

            self.entity_mapping = json.load(f)

        # -----------------------------
        # Create GNN
        # -----------------------------

        self.gnn = UPI_GNN(
            input_dim=15,
            edge_dim=15,
            hidden_dim=64,
            embedding_dim=32
        ).to(self.device)

        # -----------------------------
        # Load GNN weights
        # -----------------------------

        gnn_path = os.path.join(
            self.model_dir,
            "upi_gnn.pth"
        )

        checkpoint = torch.load(
            gnn_path,
            map_location=self.device
        )

        if (
            isinstance(checkpoint, dict)
            and "state_dict" in checkpoint
        ):

            self.gnn.load_state_dict(
                checkpoint["state_dict"]
            )

        else:

            self.gnn.load_state_dict(
                checkpoint
            )

        self.gnn.eval()

        # -----------------------------
        # Load XGBoost
        # -----------------------------

        self.xgb_model = xgb.XGBClassifier()

        self.xgb_model.load_model(
            os.path.join(
                self.model_dir,
                "upi_xgboost.json"
            )
        )

        # -----------------------------
        # Threshold
        # -----------------------------

        self.threshold = float(
            self.model_info["threshold"]
        )

        print("================================")
        print("UPI DETECTOR INITIALIZED")
        print("================================")

        print("Device:", self.device)

        if torch.cuda.is_available():
            print("GPU:", torch.cuda.get_device_name(0))

        print("GNN features:", self.model_info["gnn_input_features"])
        print("GNN embedding:", self.model_info["gnn_embedding_features"])
        print("XGBoost features:", self.model_info["total_xgboost_features"])
        print("Threshold:", self.threshold)
        print("================================")

    def _node_id(self, prefix, value):
        """Map an external VPA component to a stable trained graph node."""
        candidates = [key for key in self.entity_mapping if key.startswith(prefix)]
        if not candidates:
            raise ValueError(f"No {prefix} entities exist in the saved UPI graph")
        digest = hashlib.sha256(value.encode("utf-8")).digest()
        return self.entity_mapping[candidates[int.from_bytes(digest[:8], "big") % len(candidates)]]

    def _graph_for_transaction(self, features, upi_id):
        """Create the saved graph's 2400-node shape for one VPA transaction."""
        node_count = int(self.config["num_graph_nodes"])
        source_id = self._node_id("USR", upi_id.split("@", 1)[0])
        destination_id = self._node_id("MRC", upi_id.split("@", 1)[1])

        node_features = torch.zeros(
            (node_count, len(GNN_FEATURE_COLUMNS)), dtype=torch.float32, device=self.device
        )
        node_features[source_id] = torch.from_numpy(features).to(self.device)
        node_features[destination_id] = torch.from_numpy(features).to(self.device)
        edge_index = torch.tensor(
            [[source_id], [destination_id]], dtype=torch.long, device=self.device
        )
        edge_attr = torch.from_numpy(features).reshape(1, -1).to(self.device)
        return Data(x=node_features, edge_index=edge_index, edge_attr=edge_attr)

    def predict(self, upi_id, transaction):
        """Run the saved GNN + XGBoost pipeline for one UPI transaction."""
        features = prepare_gnn_features(transaction)
        graph = self._graph_for_transaction(features, upi_id)

        with torch.no_grad():
            _logits, embedding = self.gnn(
                graph.x, graph.edge_index, graph.edge_attr
            )

        xgb_features = np.concatenate((embedding[0].cpu().numpy(), features)).reshape(1, -1)
        if xgb_features.shape[1] != int(self.model_info["total_xgboost_features"]):
            raise ValueError(
                f"UPI model expects {self.model_info['total_xgboost_features']} features, "
                f"got {xgb_features.shape[1]}"
            )

        probabilities = self.xgb_model.predict_proba(xgb_features)[0]
        classes = list(self.xgb_model.classes_)
        fraud_probability = float(probabilities[classes.index(1)])
        if fraud_probability >= 0.7:
            verdict = "scam"
        elif fraud_probability >= self.threshold:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "verdict": verdict,
            "confidence": round(float(max(probabilities)) * 100, 1),
            "risk": round(fraud_probability * 100, 1),
            "fraud_probability": fraud_probability,
        }


def parse_upi_payload(payload, amount=None, note=""):
    """Convert a VPA or UPI payment URI into detector inputs."""
    text = str(payload or "").strip()
    parsed = urlparse(text)
    if parsed.scheme.lower() == "upi" and parsed.netloc.lower() == "pay":
        params = parse_qs(parsed.query)
        upi_id = (params.get("pa") or [""])[0].strip()
        if amount in (None, ""):
            amount = (params.get("am") or [0])[0]
        if not note:
            note = (params.get("tn") or [""])[0].strip()
    else:
        upi_id = text

    try:
        amount_text = str(amount or "").strip()
        amount_text = re.sub(r"(?i)\binr\b", "", amount_text)
        amount_text = amount_text.replace(",", "").replace("₹", "").strip()
        amount_value = float(amount_text or 0)
    except (TypeError, ValueError):
        raise ValueError("UPI amount must be a valid number") from None

    now = datetime.now()
    transaction = {
        "amount": amount_value,
        "hour_of_day": now.hour,
        "is_weekend": int(now.weekday() >= 5),
        "is_night_transaction": int(now.hour < 6 or now.hour >= 22),
        "time_since_last_txn_min": 0.0,
        "user_avg_monthly_txn": 0.0,
        "user_avg_txn_value": amount_value,
        "user_loyalty_score": 0.0,
        "new_device_flag": 0,
        "ip_location_mismatch": 0,
        "failed_attempts_last_24h": 0,
        "transaction_velocity": 0.0,
        "amount_deviation_score": 0.0,
        "recurring_payment_flag": 0,
        "balance_after_transaction": 0.0,
    }
    return upi_id, amount_value, note, transaction
if __name__ == "__main__":

    detector = UPIDetector()

    print("\n✅ UPI detector loaded successfully!")