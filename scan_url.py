from flask import Flask, request, jsonify
import joblib
import re
import os

app = Flask(__name__)

# --- 1. Load model ---
MODEL_PATH = os.path.join("model", "malicious_qr_model.pkl")
model = joblib.load(MODEL_PATH)
print("Model loaded successfully")

# --- 2. Feature extractor ---
def extract_features(url):
    url = url.lower()
    features = [
        len(url),                         # URL length
        url.count('.'),                   # number of dots
        int(url.startswith('https')),     # https?
        int(bool(re.search(r'login|verify|secure|account', url))),
        url.count('-') + url.count('_'),  # hyphens and underscores
        int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', url))),  # IP as domain
        int(bool(re.search(r'\?', url)))  # query params
    ]
    return features

# --- 3. URL analysis ---
def analyze_url(url):
    features = extract_features(url)

    # Pad to 84 features
    if len(features) < 84:
        features += [0] * (84 - len(features))

    prediction = model.predict([features])[0]
    probs = model.predict_proba([features])[0]

    risk_score = round(probs[1] * 100, 2)
    verdict = "Malicious" if prediction == 1 else "Safe"

    reasons = []
    if len(url) > 50:
        reasons.append("URL is very long")
    if re.search(r'login|verify|secure|account', url):
        reasons.append("Contains suspicious keywords")
    if re.match(r'\d+\.\d+\.\d+\.\d+', url):
        reasons.append("Uses IP address instead of domain")
    if '-' in url or '_' in url:
        reasons.append("Contains hyphens or underscores")
    if '?' in url:
        reasons.append("Contains query parameters")
    if not reasons:
        reasons.append("No obvious suspicious patterns detected")

    return risk_score, verdict, reasons

# --- 4. Routes ---
@app.route("/")
def home():
    return "Malicious QR / URL Detection API is running"

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL not provided"}), 400

    url = data["url"]

    try:
        risk, verdict, reasons = analyze_url(url)
        return jsonify({
            "url": url,
            "verdict": verdict,
            "risk_score": f"{risk}%",
            "reasons": reasons
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- 5. Run locally ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
