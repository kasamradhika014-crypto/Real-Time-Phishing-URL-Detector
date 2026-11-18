import numpy as np
import streamlit as st
from sklearn.ensemble import RandomForestClassifier

st.set_page_config(page_title="Phishing & Malicious URL Detector", layout="centered")
st.title("Real-Time Phishing & Malicious URL Detector")
st.caption("Lexical Feature Engineering + Random Forest Classifier (No External APIs)")

KEYWORDS = ["login", "verify", "update", "kyc", "bank", "free", "reward", "upi", "secure", "account"]

def extract_features(url: str) -> list[int]:
    """Convert any URL string into 7 numerical security features."""
    u = url.lower().strip()
    return [
        len(u),                                    # 1. Total URL length
        u.count("."),                              # 2. Subdomain dot count
        u.count("-"),                              # 3. Hyphen count
        1 if "@" in u else 0,                      # 4. '@' redirect trick
        1 if u.startswith("https://") else 0,      # 5. HTTPS encryption check
        sum(c.isdigit() for c in u),               # 6. Digit count in URL
        sum(word in u for word in KEYWORDS),       # 7. High-risk trap keywords
    ]

# Training dataset: 0 = Safe Website, 1 = Phishing / Malicious Link
SAMPLE_URLS = [
    ("https://www.google.com", 0),
    ("https://github.com/kasamradhika014-crypto", 0),
    ("https://www.onlinesbi.sbi", 0),
    ("https://www.cognizant.com/in/en/careers", 0),
    ("https://www.irctc.co.in/nget/train-search", 0),
    ("https://docs.python.org/3/library/heapq.html", 0),
    ("https://www.linkedin.com/jobs", 0),
    ("https://www.amazon.in/gp/css/homepage.html", 0),
    ("https://www.hdfcbank.com", 0),
    ("https://www.npci.org.in/what-we-do/upi", 0),
    ("http://sbi-kyc-update.verify-account-now.xyz/login", 1),
    ("http://paytm-upi-reward-claim.tk/secure/verify", 1),
    ("http://192.168.1.45/bank-login-update-kyc.php", 1),
    ("https://amazon-free-gift-card-winner-2026.club/claim", 1),
    ("http://hdfc-netbanking-verify@evil-site.com/login", 1),
    ("http://irctc-ticket-refund-update-account.info/upi", 1),
    ("http://cognizant-offer-letter-verify-bank.xyz/free", 1),
    ("http://google-security-alert-account-update.top/login", 1),
    ("http://free-recharge-upi-reward-claim-2026.xyz", 1),
    ("http://phonepe-kyc-blocked-account-verify.in/login", 1),
]

@st.cache_resource
def train_model():
    X = np.array([extract_features(url) for url, _ in SAMPLE_URLS])
    y = np.array([label for _, label in SAMPLE_URLS])
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf

model = train_model()

url_input = st.text_input(
    "Paste any website URL or suspicious SMS/WhatsApp link to scan:",
    value="http://sbi-kyc-update.verify-account-now.xyz/login"
)

if st.button("Scan URL Security", type="primary"):
    if not url_input.strip():
        st.warning("Please enter a URL to analyze.")
    else:
        feats = extract_features(url_input)
        pred = model.predict([feats])[0]
        prob = model.predict_proba([feats])[0][1] * 100

        c1, c2 = st.columns(2)
        c1.metric("Security Verdict", "PHISHING RISK" if pred == 1 else "SAFE LINK")
        c2.metric("Phishing Risk Score", f"{prob:.1f}%")

        # Explainable Red Flags
        red_flags = []
        if feats[0] > 50:
            red_flags.append(f"Unusually long URL ({feats[0]} characters)")
        if feats[1] > 3:
            red_flags.append(f"Excessive subdomains ({feats[1]} dots)")
        if feats[2] >= 2:
            red_flags.append(f"Multiple hyphens in domain ({feats[2]} hyphens)")
        if feats[3] == 1:
            red_flags.append("Contains '@' symbol (browser redirect trick)")
        if feats[4] == 0:
            red_flags.append("Missing HTTPS encryption (insecure HTTP)")
        if feats[6] >= 1:
            red_flags.append(f"Contains {feats[6]} trap keyword(s) (e.g., kyc, verify, login, upi)")

        if red_flags:
            st.error("**Triggered Security Red Flags:**\n" + "\n".join(f"- {f}" for f in red_flags))
        else:
            st.success("No suspicious lexical patterns or trap keywords detected.")
