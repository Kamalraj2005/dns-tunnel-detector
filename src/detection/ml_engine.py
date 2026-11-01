"""
Machine Learning Classifier for DNS Tunneling Detection.
Trains and executes a Random Forest Classifier with feature importance analysis
and anomaly scoring.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from ..features.extractor import ML_FEATURE_NAMES, extract_features_from_query, get_ml_feature_vector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_model.joblib")

class TunnelingMLClassifier:
    """
    Random Forest Machine Learning model for supervised detection of DNS tunneling.
    """
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_names = ML_FEATURE_NAMES
        self.load_or_train()

    def load_or_train(self):
        """
        Loads saved model if available; otherwise trains an initial baseline model.
        """
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data.get("model")
                return
            except Exception as e:
                print(f"Warning: Failed loading saved model ({e}), retraining baseline...")
        
        self.train_baseline_model()

    def train_baseline_model(self):
        """
        Generates a robust synthetic training set of benign DNS queries and realistic
        DNS tunneling samples (dnscat2, iodine, exfiltration chunks) and trains the classifier.
        """
        X = []
        y = []

        # 1. Representative Benign Samples
        benign_queries = [
            ("google.com", "A"), ("mail.google.com", "A"), ("smtp.office365.com", "A"),
            ("api.github.com", "A"), ("raw.githubusercontent.com", "A"),
            ("en.wikipedia.org", "A"), ("aws.amazon.com", "A"),
            ("us-east-1.console.aws.amazon.com", "A"), ("cdn.cloudflare.com", "A"),
            ("static.xx.fbcdn.net", "A"), ("e1029.g.akamaiedge.net", "CNAME"),
            ("v10.events.data.microsoft.com", "A"), ("login.live.com", "A"),
            ("netflix.com", "A"), ("assets.nflxext.com", "A"),
            ("google.com", "TXT"), ("github.com", "TXT"), # SPF records
            ("news.ycombinator.com", "A"), ("apple.com", "A"),
            ("gateway.icloud.com", "A"), ("dns.google", "A"),
            ("one.one.one.one", "A"), ("zoom.us", "A"), ("slack.com", "A"),
            ("chat.openai.com", "A"), ("cdn.jsdelivr.net", "A"),
            ("fonts.googleapis.com", "A"), ("img.youtube.com", "A")
        ]

        for qname, qtype in benign_queries:
            feats = extract_features_from_query(qname, record_type=qtype)
            X.append(get_ml_feature_vector(feats))
            y.append(0)  # 0 = Benign

        # 2. Representative Tunneling Samples (dnscat2, iodine, base32/base64 chunks)
        tunnel_queries = [
            ("01a748c08920bc49102837190283a001.c2.darknet-tunnel.org", "TXT"),
            ("b64-dGhpcyBpcyBhIHNlY3JldCBleGZpbHRyYXRpb24gcGF5bG9hZA==.exfil.attacker.xyz", "TXT"),
            ("base32-mnwxg2ltoqxg43vmn5zgo===.tunnel.evil-operator.com", "CNAME"),
            ("4a7f9c2d1b8e6a3f5c0e2d4a7b9c1e3f5a7d9b2c.ns1.tunnel-server.net", "A"),
            ("iodine.7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f.tunnel.biz", "NULL"),
            ("dnscat.01000000000000010000000000000000.tunnel.domain.com", "TXT"),
            ("exfil-part01.c3RhY2tfdHJhY2VfZHVtcF8yMDI2.attacker-dns.io", "TXT"),
            ("exfil-part02.c3FsaXRlX2RiX3Bhc3N3b3Jkc19oYXNo.attacker-dns.io", "TXT"),
            ("8fbc2910ad3e77840192a838df290bca88921.c2.victim-exfil.com", "A"),
            ("dnscat.cmd-exec-whoami-output-root-admin.tunnel.io", "TXT"),
            ("f890234ac98012e89f0128490a0c98f12.sync.tunnel-c2.net", "CNAME"),
            ("987a0fbc654de123ca890123ef456789.data.stealth-dns.com", "NULL"),
            ("data-chunk-001-4d5a90000300000004000000ffff.exfiltration.cc", "TXT"),
            ("secret-token-bearer-eyjhabgcaioijkv1q.exfil.hacker.com", "A"),
            ("c4ca4238a0b923820dcc509a6f75849b.payload.dnstunnel.org", "TXT"),
            ("28c8edde3d61a0411511d3b1866f0636.c2.remote-agent.xyz", "TXT")
        ]

        for qname, qtype in tunnel_queries:
            feats = extract_features_from_query(qname, record_type=qtype)
            X.append(get_ml_feature_vector(feats))
            y.append(1)  # 1 = Malicious Tunnel

        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)
        rf.fit(np.array(X), np.array(y))
        
        self.model = rf
        joblib.dump({"model": self.model, "feature_names": self.feature_names}, self.model_path)

    def predict(self, features: dict) -> dict:
        """
        Runs ML inference on a query feature dictionary.
        Returns:
            ml_score: float (0.0 to 100.0)
            probability: float (0.0 to 1.0)
            is_anomaly: bool
            top_features: list of (feature_name, importance_weight)
        """
        if self.model is None:
            self.load_or_train()

        vec = np.array([get_ml_feature_vector(features)])
        proba = self.model.predict_proba(vec)[0]
        tunnel_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        # Get feature importances to explain model decision
        importances = self.model.feature_importances_
        feature_impact = []
        for name, imp, val in zip(self.feature_names, importances, vec[0]):
            feature_impact.append({
                "feature": name,
                "value": round(float(val), 2),
                "importance": round(float(imp), 4)
            })
        feature_impact.sort(key=lambda x: x["importance"], reverse=True)

        return {
            "ml_score": round(tunnel_prob * 100, 2),
            "tunnel_probability": round(tunnel_prob, 4),
            "is_anomaly": bool(tunnel_prob >= 0.50),
            "top_features": feature_impact[:5]
        }
