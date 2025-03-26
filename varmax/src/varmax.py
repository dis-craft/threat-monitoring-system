import numpy as np
import torch
import torch.nn.functional as F
from tqdm import tqdm

class VarMaxScorer:
    def __init__(self, model, top_two_threshold=0.1, varmax_threshold=10, device="cpu"):
        self.model = model
        self.top_two_threshold = top_two_threshold
        self.varmax_threshold = varmax_threshold
        self.device = device

    def compute_scores(self, data_loader):
        self.model.eval()
        varmax_scores = []
        ground_truth = []

        for inputs, labels in tqdm(data_loader, desc="Computing VarMax Scores"):
            inputs = inputs.to(self.device)

            with torch.no_grad():
                logits = self.model(inputs)
                softmax = F.softmax(logits, dim=1)
                top_probs, _ = torch.topk(softmax, 2, dim=1)
                top_diff = (top_probs[:, 0] - top_probs[:, 1]).cpu().numpy()
                logits_np = logits.cpu().numpy()

            for i in range(inputs.size(0)):
                variance = np.var(np.abs(logits_np[i]))
                if top_diff[i] > self.top_two_threshold:
                    ground_truth.append(0)
                else:
                    if variance < self.varmax_threshold:
                        ground_truth.append(1)
                    else:
                        ground_truth.append(0)
                varmax_scores.append(variance)

        return varmax_scores, ground_truth
