import os
import torch

from upi_gnn_model import UPI_GNN


MODEL_PATH = os.path.join(
    "models",
    "upi",
    "upi_gnn.pth"
)

print("===== LOADING SAVED UPI GNN =====")

device = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

print("Device:", device)

# Create exact architecture
model = UPI_GNN(
    input_dim=15,
    edge_dim=15,
    hidden_dim=64,
    embedding_dim=32
).to(device)

print("\nArchitecture created:")
print(model)

# Load saved weights
checkpoint = torch.load(
    MODEL_PATH,
    map_location=device
)

# Handle either state_dict or checkpoint dictionary
if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
    model.load_state_dict(
        checkpoint["state_dict"]
    )
else:
    model.load_state_dict(
        checkpoint
    )

model.eval()

print("\nGNN loaded successfully ✅")

print(
    "Total parameters:",
    sum(
        p.numel()
        for p in model.parameters()
    )
)

print("\n================================")
print("✅ SAVED GNN VERIFIED")
print("================================")