import torch
from torch_geometric.data import Data

from upi_gnn_model import UPI_GNN


print("===== UPI GNN GRAPH COMPATIBILITY TEST =====")


# --------------------------------------------------
# Device
# --------------------------------------------------

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("Device:", device)


# --------------------------------------------------
# Create model
# --------------------------------------------------

model = UPI_GNN(
    input_dim=15,
    edge_dim=15,
    hidden_dim=64,
    embedding_dim=32
)

model.load_state_dict(
    torch.load(
        "models/upi/upi_gnn.pth",
        map_location=device,
        weights_only=True
    )
)

model = model.to(device)
model.eval()

print("GNN model loaded")


# --------------------------------------------------
# Create 2400 node features
# --------------------------------------------------

num_nodes = 2400
num_edges = 1

x = torch.randn(
    num_nodes,
    15,
    dtype=torch.float32
)


# --------------------------------------------------
# One user -> one merchant edge
# --------------------------------------------------

edge_index = torch.tensor(
    [
        [0],
        [2000]
    ],
    dtype=torch.long
)


# --------------------------------------------------
# 15 edge features
# --------------------------------------------------

edge_attr = torch.randn(
    num_edges,
    15,
    dtype=torch.float32
)


# --------------------------------------------------
# Move to GPU
# --------------------------------------------------

x = x.to(device)
edge_index = edge_index.to(device)
edge_attr = edge_attr.to(device)


# --------------------------------------------------
# Create graph
# --------------------------------------------------

graph = Data(
    x=x,
    edge_index=edge_index,
    edge_attr=edge_attr
)


print("\nGraph:")
print(graph)


# --------------------------------------------------
# Run GNN
# --------------------------------------------------

with torch.no_grad():

    logits, embeddings = model(
        graph.x,
        graph.edge_index,
        graph.edge_attr
    )


# --------------------------------------------------
# Results
# --------------------------------------------------

print("\n===== OUTPUT =====")

print(
    "Logits shape:",
    logits.shape
)

print(
    "Embedding shape:",
    embeddings.shape
)

print(
    "Expected logits:",
    "(1, 2)"
)

print(
    "Expected embedding:",
    "(1, 32)"
)


# --------------------------------------------------
# Safety checks
# --------------------------------------------------

print(
    "Logits NaN:",
    torch.isnan(logits).any().item()
)

print(
    "Embedding NaN:",
    torch.isnan(embeddings).any().item()
)


if (
    logits.shape == (1, 2)
    and embeddings.shape == (1, 32)
    and not torch.isnan(logits).any()
    and not torch.isnan(embeddings).any()
):

    print(
        "\n✅ GNN GRAPH COMPATIBILITY TEST PASSED"
    )

else:

    print(
        "\n❌ GNN GRAPH COMPATIBILITY TEST FAILED"
    )