# Real-Time Phishing & Malicious URL Detector

A machine learning cybersecurity web application that detects phishing and fraudulent links in real time using **Lexical URL Feature Engineering** and a **Random Forest Classifier**—with zero reliance on external third-party APIs.

## How It Works
1. **Lexical Feature Extraction ($O(N)$ String Parsing):** Extracts 7 structural security signals directly from the raw URL string (`url_length`, `dot_count`, `hyphen_count`, `@` redirect symbol, `HTTPS` protocol check, `digit_count`, and high-risk phishing keywords).
2. **Supervised ML Classification:** Trains a `RandomForestClassifier` (`n_estimators=100`) on labeled legitimate and malicious URL patterns to compute a real-time **Phishing Risk Probability (%)**.
3. **Explainable Security Red Flags:** Displays human-readable reasons explaining *why* a URL was flagged so non-technical users can verify suspicious SMS/WhatsApp links safely.

## Tech Stack
- **Language:** Python 3
- **Machine Learning:** Scikit-learn (`RandomForestClassifier`), NumPy
- **Web Interface & Deployment:** Streamlit Community Cloud
