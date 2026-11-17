import json
import pandas as pd
import streamlit as st
from pathlib import Path
from datetime import datetime

from backend.detector import analyze_message

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "fake_job_postings.csv"
EVALUATION_PATH = BASE_DIR / "reports" / "evaluation.json"

st.set_page_config(
    page_title="ScamShield AI | Cyber Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "offer_message" not in st.session_state:
    st.session_state.offer_message = ""

if "latest_result" not in st.session_state:
    st.session_state.latest_result = None

if "latest_message" not in st.session_state:
    st.session_state.latest_message = ""

if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0

if "checklist_done" not in st.session_state:
    st.session_state.checklist_done = []

SAMPLES = {
    "Internship registration fee scam": (
        "Congratulations! You are selected for our internship. "
        "Pay a registration fee of Rs. 1500 today to confirm your seat."
    ),
    "OTP and UPI fraud": (
        "Your internship stipend is ready. Share your OTP and UPI PIN "
        "to receive the payment immediately."
    ),
    "Fake security deposit": (
        "You have been selected. Pay a refundable security deposit "
        "of Rs. 2000 before onboarding."
    ),
    "Urgent selection scam": (
        "You are selected without an interview. Pay Rs. 1500 immediately "
        "to receive your internship offer letter. Only 5 seats are available. "
        "Contact us through WhatsApp for payment."
    ),
    "Normal internship message": (
        "Thank you for applying. We would like to invite you for an online "
        "interview next week. No registration fee is required."
    )
}


st.markdown("""
<style>
.stApp {
    background: #07111F;
    color: #EAF2FF;
}
[data-testid="stSidebar"] {
    background: #0B192B;
    border-right: 1px solid #1B3550;
}
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}
h1, h2, h3 {
    color: #F2F7FF !important;
}
p, label, .stMarkdown {
    color: #C6D5E7;
}
.hero {
    background: linear-gradient(120deg, #102C48, #172044, #102B3A);
    border: 1px solid #285477;
    border-radius: 22px;
    padding: 30px;
    margin-bottom: 22px;
}
.hero-tag {
    color: #51E5D0;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 2px;
}
.hero-title {
    color: white;
    font-size: 38px;
    font-weight: 850;
    margin: 10px 0;
}
.hero-subtitle {
    color: #B8CDE2;
    font-size: 15px;
}
.metric-card {
    background: linear-gradient(145deg, #10243A, #0D1C30);
    border: 1px solid #24415D;
    border-radius: 17px;
    padding: 19px;
    min-height: 115px;
}
.metric-label {
    color: #9DB4CC;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.metric-value {
    color: #FFFFFF;
    font-size: 30px;
    font-weight: 800;
    margin-top: 7px;
}
.panel {
    background: #0D1D30;
    border: 1px solid #203B56;
    border-radius: 18px;
    padding: 20px;
    margin: 12px 0;
}
.small-muted {
    color: #91A9C2;
    font-size: 12px;
}
.section-label {
    color: #51E5D0;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 1.5px;
}
div.stButton > button {
    border-radius: 11px;
    border: 1px solid #3B8EAA;
    background: linear-gradient(100deg, #087F8C, #3656A6);
    color: white;
    font-weight: 750;
    min-height: 43px;
}
div.stButton > button:hover {
    border: 1px solid #6AF5E4;
    color: white;
    background: linear-gradient(100deg, #099AA4, #4C68C4);
}
div[data-testid="stMetric"] {
    background: #10243A;
    border: 1px solid #24415D;
    padding: 14px;
    border-radius: 14px;
}
div[data-testid="stMetric"] label {
    color: #AFC4D9;
}
textarea, input {
    background-color: #10243A !important;
    color: white !important;
}
hr {
    border-color: #203B56;
}
</style>
""", unsafe_allow_html=True)


def metric_card(label, value, symbol):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{symbol} {label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def normalize_items(items):
    if not items:
        return []
    if isinstance(items, str):
        return [items]
    output = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("name", item.get("message", str(item)))
            detail = item.get("detail", item.get("description", ""))
            output.append(f"{name}: {detail}" if detail else str(name))
        else:
            output.append(str(item))
    return output


def go_to_scanner():
    st.session_state.navigation = "🔍 Smart Scanner"


def go_to_analytics():
    st.session_state.navigation = "📊 AI Analytics"

def clear_message():
    st.session_state.offer_message = ""

def load_sample():
    selected = st.session_state.sample_choice
    st.session_state.offer_message = SAMPLES[selected]


def display_result(result):
    score = int(result.get("risk_score", 0) or 0)
    score = max(0, min(100, score))
    level = str(result.get("risk_level", "Unknown")).upper()

    if score >= 80:
        color = "#FF5268"
        icon = "🚨"
        message = "Critical warning: do not proceed with this offer."
    elif score >= 60:
        color = "#FF9C43"
        icon = "⚠️"
        message = "High risk: verify the company independently."
    elif score >= 30:
        color = "#F2D15C"
        icon = "🔎"
        message = "Caution: investigate these warning signs."
    else:
        color = "#46D6A2"
        icon = "🛡️"
        message = "Low detected risk, but still verify before accepting."

    st.markdown(
        f"""
        <div class="panel">
            <div class="section-label">SCAMSHIELD THREAT ASSESSMENT</div>
            <h2>{icon} {level} RISK</h2>
            <div style="font-size:54px;font-weight:900;color:{color};">
                {score}<span style="font-size:20px;color:#AFC4D9;"> / 100</span>
            </div>
            <div style="height:12px;background:#263B50;border-radius:20px;overflow:hidden;">
                <div style="height:12px;width:{score}%;background:{color};border-radius:20px;"></div>
            </div>
            <p style="margin-top:15px;">{message}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    reasons = normalize_items(result.get("reasons", []))
    positives = normalize_items(result.get("positive_signals", []))
    advice = normalize_items(result.get("advice", []))

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🚩 Warning signs detected")
        if reasons:
            for item in reasons:
                st.error(item)
        else:
            st.info("No specific warning signs were returned by the detector.")

    with col2:
        st.markdown("### ✅ Positive signals")
        if positives:
            for item in positives:
                st.success(item)
        else:
            st.info("No positive signals were identified.")

    st.markdown("### 🧠 Recommended safety actions")
    if advice:
        for number, item in enumerate(advice, 1):
            st.markdown(f"**{number}.** {item}")
    else:
        st.info(
            "Verify the employer through its official website and contact details. "
            "Never share OTPs, UPI PINs or banking passwords."
        )

    model_score = result.get("model_score")
    if model_score is not None:
        st.caption(f"Model score returned by detector: {model_score}")

    st.warning(
        "This is an AI-assisted screening result, not proof that an offer is genuine "
        "or fraudulent. A low score does not guarantee safety. Verify independently."
    )


def load_json(path):
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


# SIDEBAR
with st.sidebar:
    st.markdown("## 🛡️ ScamShield AI")
    st.caption("Student Cyber Safety Platform")
    st.divider()

    page = st.radio(
    "NAVIGATION",
    [
        "🏠 Command Centre",
        "🔍 Smart Scanner",
        "📊 AI Analytics",
        "🧾 Scan History",
        "🛡️ Safety Centre",
        "ℹ️ About Project"
    ],
    key="navigation"
    )

    st.divider()
    st.markdown("### SYSTEM STATUS")
    st.success("Detection engine connected")
    st.info("Session-based scan history")
    st.caption("ScamShield AI • Student Edition")
    st.caption("Built for safer internship searching")


# HEADER
st.markdown("""
<div class="hero">
    <div class="hero-tag">CYBER DEFENCE • AI INTELLIGENCE • STUDENT SAFETY</div>
    <div class="hero-title">SCAMSHIELD AI</div>
    <div class="hero-subtitle">
        Your intelligent shield against fake internships, fraudulent job offers
        and digital recruitment scams.
    </div>
</div>
""", unsafe_allow_html=True)


# COMMAND CENTRE
if page == "🏠 Command Centre":
    st.markdown("## ⚡ Security Command Centre")
    st.write("Monitor your scans, explore the scanner and stay alert to recruitment fraud.")

    total = len(st.session_state.scan_history)
    high = sum(
        1 for item in st.session_state.scan_history
        if item["risk_score"] >= 60
    )
    low = total - high

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Total scans", total, "🔍")
    with c2:
        metric_card("High-risk alerts", high, "🚨")
    with c3:
        metric_card("Lower-risk scans", low, "🛡️")
    with c4:
        metric_card("Current session", "ACTIVE", "🟢")

    st.markdown("### 🚀 Quick Actions")
    a, b = st.columns(2)

    with a:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### 🔍 Smart Offer Scanner")
        st.write("Inspect internship messages and identify suspicious patterns.")
        st.button(
            "Open Smart Scanner",
            key="quick_open_scanner",
            use_container_width=True,
            on_click=go_to_scanner
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with b:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### 📊 Fraud Intelligence")
        st.write("Explore your scan statistics and model evaluation.")
        st.button(
            "Explore Analytics",
            key="quick_open_analytics",
            use_container_width=True,
            on_click=go_to_analytics
)       
        st.markdown("</div>", unsafe_allow_html=True)

    if st.session_state.scan_history:
        st.markdown("### 📡 Recent Security Activity")
        recent = pd.DataFrame(st.session_state.scan_history[-5:][::-1])
        st.dataframe(
            recent[["time", "risk_level", "risk_score"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.markdown("""
        <div class="panel">
            <h3>👋 Welcome, Cyber Defender!</h3>
            <p>Your security activity will appear here after your first scan.</p>
            <p>Try the Smart Scanner with one of the built-in demo messages.</p>
        </div>
        """, unsafe_allow_html=True)


# SMART SCANNER
elif page == "🔍 Smart Scanner":
    st.markdown("## 🔍 Smart Internship Offer Scanner")
    st.write("Paste an internship or job message to analyse its potential risk.")

    st.markdown('<div class="section-label">DEMO LAB • TRY A SAMPLE MESSAGE</div>',
                unsafe_allow_html=True)

    st.selectbox(
        "Choose a sample scenario",
        list(SAMPLES.keys()),
        key="sample_choice"
    )

    x, y = st.columns(2)
    with x:
        st.button(
            "✨ Load Sample Message",
            on_click=load_sample,
            use_container_width=True
        )
    with y:
        st.button(
            "🧹 Clear Message",
            on_click=clear_message,
            use_container_width=True
        )

    with st.form("scanner_form"):
        message = st.text_area(
            "Paste the received offer, email or WhatsApp message",
            key="offer_message",
            height=210,
            placeholder="Example: Congratulations! You have been selected..."
        )

        c1, c2 = st.columns(2)
        with c1:
            sender_email = st.text_input(
                "Sender email (optional)",
                placeholder="hr@company.com"
            )
        with c2:
            company_domain = st.text_input(
                "Official company domain (optional)",
                placeholder="company.com"
            )

        submitted = st.form_submit_button(
            "🛡️ ANALYSE OFFER NOW",
            use_container_width=True
        )

    if submitted:
        if not message.strip():
            st.warning("Please paste a message before starting the scan.")
        else:
            with st.spinner("AI engine is analysing the offer..."):
                try:
                    result = analyze_message(
                        message,
                        sender_email.strip(),
                        company_domain.strip()
                    )

                    score = int(result.get("risk_score", 0) or 0)
                    level = str(result.get("risk_level", "Unknown"))

                    st.session_state.latest_result = result
                    st.session_state.latest_message = message
                    st.session_state.scan_count += 1

                    st.session_state.scan_history.append({
                        "time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                        "risk_score": score,
                        "risk_level": level,
                        "message": message,
                        "sender_email": sender_email,
                        "company_domain": company_domain,
                        "reasons": normalize_items(result.get("reasons", [])),
                        "advice": normalize_items(result.get("advice", []))
                    })

                    st.success("Analysis completed successfully!")

                except Exception as error:
                    st.error(f"Scanner error: {error}")

    if st.session_state.latest_result is not None:
        st.divider()
        st.markdown("## 📋 Latest Intelligence Report")
        display_result(st.session_state.latest_result)

        report = {
            "project": "ScamShield AI",
            "generated_at": datetime.now().isoformat(),
            "message": st.session_state.latest_message,
            "analysis": st.session_state.latest_result
        }

        st.download_button(
            "⬇️ Download Full Scan Report (JSON)",
            data=json.dumps(report, indent=4, default=str),
            file_name="scamshield_scan_report.json",
            mime="application/json",
            use_container_width=True
        )


# ANALYTICS
elif page == "📊 AI Analytics":
    st.markdown("## 📊 AI Fraud Intelligence & Analytics")
    st.write("Explore scan activity and the performance information saved by your model.")

    history = st.session_state.scan_history

    if history:
        df = pd.DataFrame(history)

        total = len(df)
        average = round(df["risk_score"].mean(), 1)
        high = int((df["risk_score"] >= 60).sum())

        a, b, c = st.columns(3)
        a.metric("Total messages scanned", total)
        b.metric("Average risk score", f"{average}/100")
        c.metric("High-risk messages", high)

        st.markdown("### 📈 Risk score across scans")
        chart_df = df.reset_index()
        chart_df["Scan"] = chart_df.index + 1
        st.line_chart(chart_df.set_index("Scan")[["risk_score"]])

        st.markdown("### 🎯 Risk category distribution")
        distribution = (
            df["risk_level"]
            .value_counts()
            .rename_axis("Risk Level")
            .to_frame("Scans")
        )
        st.bar_chart(distribution)

    else:
        st.info("Run a few messages through the Smart Scanner to generate live analytics.")

    st.divider()
    st.markdown("### 🧪 Machine Learning Model Evaluation")

    evaluation = load_json(EVALUATION_PATH)

    if evaluation:
        metric_names = [
            ("accuracy", "Accuracy"),
            ("precision", "Precision"),
            ("recall", "Recall"),
            ("f1_score", "F1 Score"),
            ("average_precision", "Average Precision")
        ]

        available = [
            (label, evaluation[key])
            for key, label in metric_names
            if key in evaluation and isinstance(evaluation[key], (int, float))
        ]

        if available:
            cols = st.columns(len(available))
            for col, (label, value) in zip(cols, available):
                col.metric(label, f"{value:.3f}")

        matrix = evaluation.get("confusion_matrix")
        if matrix:
            st.markdown("#### Confusion Matrix")
            st.dataframe(
                pd.DataFrame(
                    matrix,
                    index=["Actual genuine", "Actual fraudulent"],
                    columns=["Predicted genuine", "Predicted fraudulent"]
                ),
                use_container_width=True
            )

        st.caption(
            "These are saved model evaluation results. They are separate from "
            "the live session scans shown above."
        )
    else:
        st.info("No evaluation report found. Train your model to generate evaluation.json.")


# SCAN HISTORY
elif page == "🧾 Scan History":
    st.markdown("## 🧾 Security Scan History")
    st.write("Review the messages analysed during this current session.")

    history = st.session_state.scan_history

    if history:
        df = pd.DataFrame(history)

        st.dataframe(
            df[["time", "risk_level", "risk_score", "sender_email"]],
            use_container_width=True,
            hide_index=True
        )

        st.markdown("### 🔎 Inspect an individual scan")
        options = list(range(len(history)))
        selected = st.selectbox(
            "Select scan number",
            options,
            format_func=lambda i: (
                f"Scan {i + 1} • {history[i]['risk_level']} • "
                f"{history[i]['risk_score']}/100"
            )
        )

        chosen = history[selected]
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("**Original message**")
        st.write(chosen["message"])
        st.markdown("**Detected warning signs**")
        for reason in chosen["reasons"]:
            st.write("🚩", reason)
        st.markdown("**Recommended actions**")
        for advice in chosen["advice"]:
            st.write("🛡️", advice)
        st.markdown("</div>", unsafe_allow_html=True)

        csv_data = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Export Scan History (CSV)",
            data=csv_data,
            file_name="scamshield_scan_history.csv",
            mime="text/csv"
        )

        if st.button("🗑️ Clear Session History"):
            st.session_state.scan_history = []
            st.session_state.latest_result = None
            st.session_state.latest_message = ""
            st.rerun()

    else:
        st.info("No scans yet. Visit Smart Scanner to begin.")


# SAFETY CENTRE
elif page == "🛡️ Safety Centre":
    st.markdown("## 🛡️ Student Safety Centre")
    st.write("Use this checklist before accepting any internship or job offer.")

    checklist = [
        "I checked the company's official website.",
        "I verified the recruiter using official company contact details.",
        "I checked whether the sender email matches the company domain.",
        "I did not pay registration, training or security deposit fees.",
        "I did not share OTP, UPI PIN or banking passwords.",
        "I checked the job description and selection process.",
        "I independently verified suspicious links before opening them."
    ]

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### ✅ Internship Verification Checklist")

    completed = []
    for item in checklist:
        is_checked = st.checkbox(
            item,
            value=item in st.session_state.checklist_done,
            key=f"check_{checklist.index(item)}"
        )
        if is_checked:
            completed.append(item)

    st.session_state.checklist_done = completed

    progress = len(completed) / len(checklist)
    st.progress(progress)
    st.write(f"**{len(completed)} of {len(checklist)} checks completed**")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### 🚨 Golden Rules")
    rules = [
        ("Never pay to get selected", "Be suspicious of registration fees and refundable deposits."),
        ("Never share OTP or UPI PIN", "A recruiter does not need your banking authentication details."),
        ("Verify before you trust", "Use official company websites and independently found contact details."),
        ("Do not rush", "Urgency and limited-seat pressure can be manipulation tactics."),
        ("Report suspicious offers", "Preserve messages and report suspected fraud through appropriate official channels.")
    ]

    for title, description in rules:
        with st.expander(title):
            st.write(description)


# ABOUT
elif page == "ℹ️ About Project":
    st.markdown("## 💡 About ScamShield AI")

    st.markdown("""
    <div class="panel">
        <div class="section-label">THE PROBLEM</div>
        <h3>Students are increasingly targeted by fake internship offers.</h3>
        <p>
        Fraudsters may promise high stipends, instant selection or guaranteed
        internships while demanding fees, deposits, OTPs or sensitive information.
        </p>
    </div>
    <div class="panel">
        <div class="section-label">OUR SOLUTION</div>
        <h3>An AI-assisted recruitment fraud screening platform.</h3>
        <p>
        ScamShield AI combines machine learning and rule-based checks to identify
        suspicious language and potential recruitment fraud indicators.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ How the system works")
    steps = [
        "Student pastes an internship or job message.",
        "The detector checks suspicious words, payment requests and other signals.",
        "The machine learning model contributes a text-based assessment when available.",
        "The platform displays a risk score, warning signs and safety advice."
    ]

    for i, step in enumerate(steps, 1):
        st.markdown(f"**{i}.** {step}")

    st.markdown("### 🧰 Technology Stack")
    st.write("Python • Streamlit • Pandas • Scikit-learn • TF-IDF • Logistic Regression")

    st.warning(
        "ScamShield AI is a screening aid, not a guarantee. It does not independently "
        "verify company ownership, visit suspicious URLs or prove that a message is genuine."
    )


# FOOTER
st.divider()
st.markdown(
    """
    <div style="text-align:center;padding:15px;color:#7893AE;">
        <b style="color:#51E5D0;">🛡️ SCAMSHIELD AI</b><br>
        Intelligent protection for the next generation of professionals.<br>
        <span style="font-size:11px;">AI-assisted detection • Student awareness • Safer opportunities</span>
    </div>
    """,
    unsafe_allow_html=True
)