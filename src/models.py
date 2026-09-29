from __future__ import annotations
import json
from pathlib import Path
import joblib
import numpy as np
import torch
from torch import nn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, roc_auc_score

class LSTMForecaster(nn.Module):
    def __init__(self, n_features: int, hidden: int = 32):
        super().__init__(); self.lstm = nn.LSTM(n_features, hidden, batch_first=True); self.head = nn.Sequential(nn.Dropout(.15), nn.Linear(hidden, 1))
    def forward(self, x):
        output, _ = self.lstm(x); return self.head(output[:, -1]).squeeze(1)

def metrics(y, probability):
    result = {"accuracy_at_0.5": round(float(accuracy_score(y, probability >= .5)), 3)}
    if len(np.unique(y)) == 2:
        result["roc_auc"] = round(float(roc_auc_score(y, probability)), 3)
        result["average_precision"] = round(float(average_precision_score(y, probability)), 3)
    return result

def train_lstm(x_train, y_train, x_test, y_test, epochs=20):
    model = LSTMForecaster(x_train.shape[-1]); pos=max(1,int(y_train.sum())); neg=max(1,len(y_train)-pos)
    loss_fn=nn.BCEWithLogitsLoss(pos_weight=torch.tensor(neg/pos,dtype=torch.float32)); opt=torch.optim.Adam(model.parameters(),lr=1e-3)
    xt=torch.tensor(x_train,dtype=torch.float32); yt=torch.tensor(y_train,dtype=torch.float32)
    model.train()
    for _ in range(epochs):
        opt.zero_grad(); loss=loss_fn(model(xt),yt); loss.backward(); opt.step()
    model.eval()
    with torch.no_grad(): p=torch.sigmoid(model(torch.tensor(x_test,dtype=torch.float32))).numpy()
    return model, metrics(y_test,p)

def train_baseline(x_train,y_train,x_test,y_test):
    model=LogisticRegression(max_iter=1000,class_weight="balanced"); model.fit(x_train[:,-1,:],y_train)
    return model,metrics(y_test,model.predict_proba(x_test[:,-1,:])[:,1])

def permutation_importance(model,x,y,names,repeats=4):
    model.eval()
    with torch.no_grad(): base=metrics(y,torch.sigmoid(model(torch.tensor(x,dtype=torch.float32))).numpy()).get("average_precision",0)
    rng=np.random.default_rng(42); result=[]
    for i,name in enumerate(names):
        scores=[]
        for _ in range(repeats):
            shuffled=x.copy(); rng.shuffle(shuffled[:,:,i])
            with torch.no_grad(): score=metrics(y,torch.sigmoid(model(torch.tensor(shuffled,dtype=torch.float32))).numpy()).get("average_precision",0)
            scores.append(base-score)
        result.append({"feature":name,"importance":round(float(np.mean(scores)),4)})
    return sorted(result,key=lambda row:row["importance"],reverse=True)

def save_artifacts(folder:Path,model,scaler,baseline,metadata):
    folder.mkdir(parents=True,exist_ok=True); torch.save(model.state_dict(),folder/"lstm.pt"); joblib.dump(scaler,folder/"scaler.joblib"); joblib.dump(baseline,folder/"baseline.joblib")
    (folder/"metadata.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")

def load_lstm(folder:Path):
    metadata=json.loads((folder/"metadata.json").read_text(encoding="utf-8")); model=LSTMForecaster(len(metadata["feature_columns"]))
    model.load_state_dict(torch.load(folder/"lstm.pt",map_location="cpu",weights_only=True)); model.eval()
    return model,joblib.load(folder/"scaler.joblib"),metadata
