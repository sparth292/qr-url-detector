import joblib
import re

# --- 1. Load your model ---
MODEL_PATH = "model/malicious_qr_model.pkl"
model = joblib.load(MODEL_PATH)
print("Model loaded")

# --- 2. Feature extractor (7 features for demo) ---
def extract_features(url):
    url = url.lower()
    features = [
        len(url),                       # URL length
        url.count('.'),                  # number of dots
        int(url.startswith('https')),    # https?
        int(bool(re.search(r'login|verify|secure|account', url))),  # suspicious keywords
        url.count('-') + url.count('_'), # hyphens and underscores
        int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', url))),  # IP as domain
        int(bool(re.search(r'\?', url))) # query params
    ]
    return features

# --- 3. Analyze URL ---
def analyze_url(url):
    # Extract features
    features = extract_features(url)
    
    # Pad features to match model input (84 features)
    if len(features) < 84:
        features += [0]*(84 - len(features))

    # Predict
    prediction = model.predict([features])[0]
    probs = model.predict_proba([features])[0]

    # Generate a simple risk score and reasons
    risk_score = round(probs[1]*100, 2)  # probability of being malicious
    verdict = "Malicious" if prediction == 1 else "Safe"

    # Simple explanation
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

# --- 4. Main program ---
print("\n QR / URL Malicious Detector\n")

while True:
    url = input("Enter URL (or 'exit' to quit): ").strip()
    if url.lower() == "exit":
        break
    try:
        risk, verdict, reasons = analyze_url(url)
        print(f"\n URL Verdict: {verdict}")
        print(f" Risk Score: {risk}%")
        print("Reasons:")
        for r in reasons:
            print(f" - {r}")
        print("\n" + "-"*40 + "\n")
    except Exception as e:
        print(f"Error: {e}")
