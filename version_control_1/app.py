"""Streamlit demo. Run from this folder: streamlit run app.py"""
import os
import re
from datetime import datetime

import joblib
import pandas as pd
import streamlit as st

st.set_page_config(page_title="PhishGuard", page_icon=":material/shield:", layout="wide")

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
URL_RE = re.compile(r"https?://[^\s\"'<>]+|www\.[^\s\"'<>]+")

EXAMPLE_EMAIL = (
    "URGENT: Your account has been suspended!\n\n"
    "We detected unusual activity. Verify your password within 24 hours or your "
    "account will be locked permanently.\n"
    "Click here: http://paypa1-secure-login.xyz/verify\n\n"
    "- Security Team"
)
EXAMPLE_URL = "http://paypa1-secure-login.xyz/verify-account"


@st.cache_resource
def load(name):
    path = os.path.join(MODEL_DIR, f"{name}_model.joblib")
    return joblib.load(path) if os.path.exists(path) else None


email_model, url_model = load("email"), load("url")

if "history" not in st.session_state:
    st.session_state.history = []
st.session_state.setdefault("email_text", "")
st.session_state.setdefault("url_text", "")


def set_value(key, value):
    st.session_state[key] = value


def level(p):
    """Map phishing probability to (label, color, icon)."""
    if p >= 0.7:
        return "Phishing", "red", ":material/gpp_bad:"
    if p >= 0.4:
        return "Suspicious", "orange", ":material/warning:"
    return "Looks legitimate", "green", ":material/verified_user:"


def show_verdict(p, kind, subject):
    label, color, icon = level(p)
    with st.container(border=True):
        left, right = st.columns([1, 2], vertical_alignment="center")
        with left:
            st.metric("Phishing probability", f"{p:.0%}", border=False)
        with right:
            st.badge(label, icon=icon, color=color)
            st.progress(float(p), text=f"Risk level: {p:.0%}")
            advice = {
                "red": "Do not click links or reply. Report and delete it.",
                "orange": "Be careful. Check the sender and the link before acting.",
                "green": "No strong phishing signals found. Stay alert anyway.",
            }[color]
            st.caption(advice)
    st.session_state.history.insert(0, {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Type": kind,
        "Input": subject[:60] + ("..." if len(subject) > 60 else ""),
        "Phishing %": round(float(p) * 100),
        "Verdict": label,
    })
    del st.session_state.history[10:]


# ---------------- sidebar ----------------
with st.sidebar:
    st.header("PhishGuard", icon=":material/shield:")
    st.caption("Machine-learning phishing detector for emails and links.")

    st.subheader("Models")
    st.badge("Email model", icon=":material/mail:" if email_model else ":material/error:",
             color="green" if email_model else "red")
    st.badge("URL model", icon=":material/link:" if url_model else ":material/error:",
             color="green" if url_model else "red")
    if not (email_model and url_model):
        st.caption("Missing a model? Run `python train.py` first.")

    st.subheader("How to read results")
    st.markdown(
        ":red-badge[70%+] phishing  \n"
        ":orange-badge[40-70%] suspicious  \n"
        ":green-badge[under 40%] looks legitimate"
    )
    st.caption("Results are a prediction, not a guarantee.")

# ---------------- header ----------------
st.title("Phishing email and URL detector", icon=":material/shield:")
st.caption("Paste an email or a link. The model scores how likely it is to be phishing.")

tab_email, tab_url, tab_history = st.tabs([
    ":material/mail: Email", ":material/link: URL", ":material/history: History",
])

# ---------------- email tab ----------------
with tab_email:
    if email_model is None:
        st.warning("Train the email model first: `python train.py --email <csv>`",
                   icon=":material/model_training:")
    st.button("Load phishing example", icon=":material/science:", key="ex_email",
              on_click=set_value, args=("email_text", EXAMPLE_EMAIL))
    text = st.text_area("Email text", key="email_text", height=220,
                        placeholder="Paste the full email body here...")

    if st.button("Check email", type="primary", icon=":material/search:",
                 disabled=email_model is None):
        if not text.strip():
            st.toast("Paste some email text first.", icon=":material/info:")
        else:
            with st.spinner("Analyzing..."):
                p = email_model.predict_proba([text])[0, 1]
            show_verdict(p, "Email", text.replace("\n", " "))

            urls = list(dict.fromkeys(URL_RE.findall(text)))
            if urls and url_model is not None:
                st.subheader("Links found in this email", icon=":material/link:")
                probs = url_model.predict_proba(urls)[:, 1]
                st.dataframe(
                    pd.DataFrame({"Link": urls, "Phishing %": [round(x * 100) for x in probs]}),
                    column_config={
                        "Phishing %": st.column_config.ProgressColumn(
                            "Phishing %", min_value=0, max_value=100, format="%d%%"),
                    },
                    hide_index=True,
                    alt="Phishing probability for each link found in the email",
                )

# ---------------- URL tab ----------------
with tab_url:
    if url_model is None:
        st.warning("Train the URL model first: `python train.py --url <csv>`",
                   icon=":material/model_training:")
    st.button("Load phishing example", icon=":material/science:", key="ex_url",
              on_click=set_value, args=("url_text", EXAMPLE_URL))
    u = st.text_input("URL", key="url_text", placeholder="https://example.com/login")

    if st.button("Check URL", type="primary", icon=":material/search:",
                 disabled=url_model is None):
        if not u.strip():
            st.toast("Paste a URL first.", icon=":material/info:")
        else:
            with st.spinner("Analyzing..."):
                p = url_model.predict_proba([u.strip()])[0, 1]
            show_verdict(p, "URL", u.strip())

# ---------------- history tab ----------------
with tab_history:
    if st.session_state.history:
        st.dataframe(
            pd.DataFrame(st.session_state.history),
            column_config={"Phishing %": st.column_config.ProgressColumn(
                "Phishing %", min_value=0, max_value=100, format="%d%%")},
            hide_index=True,
            alt="Recent phishing checks from this session",
        )
        st.button("Clear history", icon=":material/delete:",
                  on_click=lambda: st.session_state.history.clear())
    else:
        st.caption("Your last 10 checks will appear here.")
