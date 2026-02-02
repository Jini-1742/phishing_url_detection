import streamlit as st
import json
import os
import re
from urllib.parse import urlparse
import difflib

# ---------------------------
# UI CONFIGURATION
# ---------------------------
st.set_page_config(
    page_title="Phishing URL Detection",
    layout="wide"
)

st.markdown("""
<style>
.stApp { background-color: #260000; }
h1, h2, h3, p, label { color: white; }
.stButton>button {
    background-color: #24D000;
    color: black;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------
# CONSTANTS & DATA
# ---------------------------
LEGIT_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "amazon.com",
    "google.com",
    "microsoft.com"
]

SUSPICIOUS_KEYWORDS = ["login", "secure", "verify", "account", "update"]

DB_FILE = "phishing_db.json"

# Load phishing database safely
if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f:
        phishing_db = json.load(f)
else:
    phishing_db = {}

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------
def is_email(text):
    return re.match(r"[^@]+@[^@]+\.[^@]+", text)

def has_ip(domain):
    return re.match(r"(\d{1,3}\.){3}\d{1,3}", domain)

def detect_phishing(input_str):
    score = 0
    reasons = []

    # EMAIL DETECTION
    if is_email(input_str):
        domain = input_str.split("@")[-1]

        if domain not in LEGIT_DOMAINS:
            score += 1
            reasons.append("Unknown email domain")

        similarity = max(
            difflib.SequenceMatcher(None, domain, legit).ratio()
            for legit in LEGIT_DOMAINS
        )

        if similarity > 0.8:
            score += 1
            reasons.append("Domain mimics a legitimate email service")

    # URL DETECTION
    else:
        parsed = urlparse(
            input_str if input_str.startswith("http") else f"http://{input_str}"
        )
        domain = parsed.netloc

        if has_ip(domain):
            score += 1
            reasons.append("IP address used instead of domain")

        if len(input_str) > 75:
            score += 1
            reasons.append("URL length is too long")

        if "@" in input_str:
            score += 1
            reasons.append("'@' symbol found in URL")

        if not input_str.startswith("https"):
            score += 1
            reasons.append("HTTPS not used")

        if any(word in input_str.lower() for word in SUSPICIOUS_KEYWORDS):
            score += 1
            reasons.append("Suspicious keywords found in URL")

        similarity = max(
            difflib.SequenceMatcher(None, domain, legit).ratio()
            for legit in LEGIT_DOMAINS
        )

        if similarity > 0.8:
            score += 1
            reasons.append("Domain mimics a legitimate website")

    if score >= 2:
        return True, "Phishing detected: " + ", ".join(reasons)
    else:
        return False, "Legitimate link or email"

# ---------------------------
# UI TABS
# ---------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Dashboard", "Check", "Rate", "Info", "Sandbox"]
)

# ---------------------------
# DASHBOARD
# ---------------------------
with tab1:
    st.header("📊 Dashboard")
    st.write("Welcome to the **Phishing URL Detection System**")
    st.write("Rule-based detection for URLs and email addresses.")
    st.write(f"**Total rated phishing entries:** {len(phishing_db)}")

    if phishing_db:
        st.subheader("Sample Stored Ratings")
        for item, rating in list(phishing_db.items())[:5]:
            st.write(f"- {item} → {rating}% illegitimate")

# ---------------------------
# CHECK PHISHING
# ---------------------------
with tab2:
    st.header("🔍 Check for Phishing")
    uploaded_file = st.file_uploader(
        "Upload TXT file (one entry per line)", type=["txt"]
    )
    input_text = st.text_area("Or enter URLs / Emails (one per line)")

    if st.button("Check Now"):
        inputs = []

        if uploaded_file:
            content = uploaded_file.read().decode("utf-8")
            inputs.extend([line.strip() for line in content.splitlines() if line.strip()])

        if input_text:
            inputs.extend([line.strip() for line in input_text.splitlines() if line.strip()])

        for inp in inputs:
            is_phish, message = detect_phishing(inp)

            if inp in phishing_db:
                st.info(f"Previous Rating: {phishing_db[inp]}% illegitimate")

            if is_phish:
                st.error(f"❌ {inp}\n\n{message}")
            else:
                st.success(f"✅ {inp}\n\n{message}")

# ---------------------------
# RATE PHISHING
# ---------------------------
with tab3:
    st.header("⭐ Rate Phishing Entries")
    entry = st.text_input("Enter URL or Email")
    rating = st.slider("Illegitimate Rating (%)", 0, 100, 50)

    if st.button("Save Rating"):
        if entry:
            phishing_db[entry] = rating
            with open(DB_FILE, "w") as f:
                json.dump(phishing_db, f, indent=4)
            st.success("Rating saved successfully")

# ---------------------------
# INFORMATION TAB
# ---------------------------
with tab4:
    st.header("ℹ️ About Phishing")
    st.write("""
    **Phishing** is a cyber attack where attackers trick users into revealing
    sensitive information using fake emails or malicious websites.
    """)

    st.subheader("Common Dangerous File Types")
    st.write("""
    - `.exe`, `.scr`
    - `.vbs`, `.js`
    - `.bat`
    - `.zip`
    - `.docm`, `.xlsm`
    """)

# ---------------------------
# SANDBOX TAB
# ---------------------------
with tab5:
    st.header("🧪 Sandbox Safety")
    st.write("""
    Do NOT open suspicious links directly.

    **Safe testing options:**
    - VirusTotal
    - Any.run
    - Hybrid Analysis
    - Virtual Machines (VMware / VirtualBox)
    """)

    link = st.text_input("Enter suspicious link")
    if st.button("Get Safe Advice"):
        if link:
            st.info(
                f"Paste **{link}** into VirusTotal or Any.run "
                "for safe analysis."
            )
