import torch
import torch.nn as nn
from torch_geometric.nn import SAGEConv


class UPI_GNN(nn.Module):

    def __init__(
        self,
        input_dim=15,
        edge_dim=15,
        hidden_dim=64,
        embedding_dim=32
    ):
        super().__init__()

        self.conv1 = SAGEConv(
            input_dim,
            hidden_dim
        )

        self.conv2 = SAGEConv(
            hidden_dim,
            embedding_dim
        )

        # 32 source embedding
        # + 32 destination embedding
        # + 15 transaction/edge features
        # = 79 input features
        self.transaction_layer = nn.Sequential(

            nn.Linear(
                embedding_dim * 2 + edge_dim,
                64
            ),

            nn.ReLU(),

            nn.Dropout(0.3),

            nn.Linear(
                64,
                embedding_dim
            ),

            nn.ReLU()
        )

        self.classifier = nn.Linear(
            embedding_dim,
            2
        )


    def forward(
        self,
        x,
        edge_index,
        edge_attr
    ):

        # Node embeddings
        x = self.conv1(
            x,
            edge_index
        )

        x = torch.relu(x)

        x = self.conv2(
            x,
            edge_index
        )

        x = torch.relu(x)

        # Source and destination nodes
        src = edge_index[0]
        dst = edge_index[1]

        src_embedding = x[src]
        dst_embedding = x[dst]

        # 32 + 32 + 15 = 79
        transaction_input = torch.cat(
            [
                src_embedding,
                dst_embedding,
                edge_attr
            ],
            dim=1
        )

        transaction_embedding = self.transaction_layer(
            transaction_input
        )

        logits = self.classifier(
            transaction_embedding
        )

        return logits, transaction_embedding