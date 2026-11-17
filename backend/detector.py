import re
from pathlib import Path

import joblib


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "scamshield_model.pkl"

FEE_TERMS = [
    "registration fee",
    "application fee",
    "processing fee",
    "training fee",
    "certificate fee",
    "security deposit",
    "refundable deposit",
    "joining fee",
    "verification fee",
    "interview fee",
]

NEGATION_PATTERNS = [
    r"\bno\s+(?:any\s+)?{term}\b",
    r"\bwithout\s+(?:any\s+)?{term}\b",
    r"\bwe\s+never\s+ask\s+(?:candidates\s+)?to\s+pay(?:\s+any)?\s+{term}\b",
    r"\bwe\s+do\s+not\s+charge\s+(?:any\s+)?{term}\b",
    r"\bdo\s+not\s+pay\s+(?:any\s+)?{term}\b",
    r"\bnever\s+pay\s+(?:any\s+)?{term}\b",
]

RULES = [
    {
        "name": "OTP or account credential request",
        "pattern": r"\b(otp|one.time.password|upi pin|atm pin|cvv|bank password|net banking password)\b",
        "points": 60,
        "severity": "CRITICAL",
        "reason": "The message mentions sensitive credentials such as an OTP, UPI PIN or banking password.",
        "advice": "Never share an OTP, UPI PIN, CVV or banking password with a recruiter.",
    },
    {
        "name": "Personal identity information request",
        "pattern": r"\b(aadhaar|pan card|passport number|bank account number)\b",
        "points": 18,
        "severity": "MODERATE",
        "reason": "The message requests sensitive identity or financial information. Check why it is needed and who is collecting it.",
        "advice": "Do not send identity or bank documents until you have independently verified the organisation and the purpose.",
    },
    {
        "name": "Urgent payment pressure",
        "pattern": r"\b(pay immediately|pay now|within \d+ hours|limited slots|last chance|urgent payment|today only|act immediately)\b",
        "points": 18,
        "severity": "HIGH",
        "reason": "The message uses urgency or pressure to encourage quick action.",
        "advice": "Pause and verify the offer independently. Do not pay because of a deadline in a message.",
    },
    {
        "name": "Guaranteed selection or placement",
        "pattern": r"\b(guaranteed selection|100% placement|job guaranteed|assured internship|direct selection without interview)\b",
        "points": 15,
        "severity": "HIGH",
        "reason": "The offer makes an unusually strong promise about selection or placement.",
        "advice": "Verify the selection process through the organisation's official careers page.",
    },
    {
        "name": "Payment to a personal account",
        "pattern": r"\b(pay to (?:my|personal) (?:account|upi)|send (?:the )?money to (?:my|personal)|personal upi id|gpay me|phonepe me)\b",
        "points": 30,
        "severity": "HIGH",
        "reason": "The message appears to direct payment to a personal account or UPI ID.",
        "advice": "Do not transfer money to a recruiter’s personal account or UPI ID.",
    },
    {
        "name": "Unusually high stipend promise",
        "pattern": r"\b(earn|stipend of|salary of)\s*(?:₹|rs\.?|inr)?\s*(?:[1-9]\d{4,}|[1-9]\d{2,}\s*(?:per day|\/day))",
        "points": 12,
        "severity": "MODERATE",
        "reason": "The message advertises an unusually high payment. This is a warning sign to verify, not proof of fraud.",
        "advice": "Compare the stipend with the role, work requirements and the organisation's official listing.",
    },
]


def _load_model():
    if not MODEL_PATH.exists():
        return None

    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def _fee_is_negated(text, term):
    escaped_term = re.escape(term)

    for pattern in NEGATION_PATTERNS:
        if re.search(pattern.format(term=escaped_term), text, flags=re.IGNORECASE):
            return True

    return False


def _find_fee_signals(text):
    found = []

    for term in FEE_TERMS:
        for match in re.finditer(re.escape(term), text, flags=re.IGNORECASE):
            start = max(0, match.start() - 90)
            end = min(len(text), match.end() + 90)
            context = text[start:end]

            if _fee_is_negated(context, term):
                continue

            # A fee or deposit is a stronger warning when the message
            # asks the candidate to pay, transfer, submit or provide it.
            payment_action = re.search(
                r"\b(pay|submit|deposit|transfer|send|remit|clear|"
                r"must pay|required|payable|payment of|fee of|deposit of)\b",
                context,
                flags=re.IGNORECASE,
            )

            # Security deposits and refundable deposits are flagged
            # even if the message does not use an explicit payment verb.
            deposit_term = "deposit" in term

            if payment_action or deposit_term:
                found.append({
                    "name": f"Possible {term} demand",
                    "severity": "HIGH",
                    "points": 35,
                    "reason": f"The message mentions a {term} in a payment-related context.",
                    "advice": "Do not pay an internship registration, training, certificate or security fee before independently verifying the organisation.",
                })
                break

    return found


def _check_urls(text):
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text, flags=re.IGNORECASE)
    findings = []

    for url in urls:
        clean_url = url.lower().rstrip(".,);]")

        suspicious_terms = [
            "bit.ly",
            "tinyurl",
            "t.me",
            "telegram.me",
            "forms.gle",
            "login-verify",
            "secure-payment",
            "free-stipend",
        ]

        if any(term in clean_url for term in suspicious_terms):
            findings.append({
                "name": "Shortened or potentially suspicious link",
                "severity": "MODERATE",
                "points": 15,
                "reason": f"The message contains a link that needs extra verification: {url}",
                "advice": "Do not enter passwords, OTPs or payment details on an unverified link. Visit the company's official website separately.",
            })
        else:
            findings.append({
                "name": "Link included in the message",
                "severity": "INFO",
                "points": 3,
                "reason": f"A link was included: {url}. Its presence alone does not prove fraud.",
                "advice": "Check the exact domain carefully before opening the link.",
            })

    return findings


def _check_sender_domain(sender_email, company_domain):
    if not sender_email or not company_domain:
        return []

    sender_email = sender_email.strip().lower()
    company_domain = company_domain.strip().lower()
    company_domain = re.sub(r"^https?://", "", company_domain)
    company_domain = company_domain.split("/")[0].removeprefix("www.")

    if "@" not in sender_email:
        return [{
            "name": "Invalid sender email format",
            "severity": "MODERATE",
            "points": 10,
            "reason": "The sender email does not appear to have a valid email format.",
            "advice": "Check the sender's complete email address.",
        }]

    sender_domain = sender_email.rsplit("@", 1)[1]

    if sender_domain in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}:
        return [{
            "name": "Free email provider used",
            "severity": "MODERATE",
            "points": 12,
            "reason": "The sender uses a free email provider rather than an apparent company email domain.",
            "advice": "This alone does not prove fraud, but verify the recruiter through the company's official contact details.",
        }]

    if sender_domain != company_domain and not sender_domain.endswith("." + company_domain):
        return [{
            "name": "Sender and company domain do not match",
            "severity": "HIGH",
            "points": 25,
            "reason": f"The sender domain ({sender_domain}) does not match the supplied company domain ({company_domain}).",
            "advice": "Contact the company using contact details from its official website, not the details in the message.",
        }]

    return []


def _get_model_score(message):
    model = _load_model()

    if model is None:
        return None

    try:
        probabilities = model.predict_proba([message])[0]
        classes = list(model.classes_)
        fraud_index = classes.index(1)
        return float(probabilities[fraud_index])
    except Exception:
        return None


def analyze_message(message, sender_email="", company_domain=""):
    message = (message or "").strip()

    if not message:
        return {
            "risk_score": 0,
            "risk_level": "NOT ANALYSED",
            "model_score": None,
            "reasons": [],
            "advice": ["Enter an internship or job offer message to analyse it."],
            "positive_signals": [],
            "model_available": _load_model() is not None,
        }

    findings = []

    for rule in RULES:
        if re.search(rule["pattern"], message, flags=re.IGNORECASE):
            findings.append({
                "name": rule["name"],
                "severity": rule["severity"],
                "points": rule["points"],
                "reason": rule["reason"],
                "advice": rule["advice"],
            })

    findings.extend(_find_fee_signals(message))
    findings.extend(_check_urls(message))
    findings.extend(_check_sender_domain(sender_email, company_domain))

    # Rule score is a heuristic, not a probability.
    rule_score = min(100, sum(item["points"] for item in findings))

    model_score = _get_model_score(message)

    if model_score is None:
        final_score = rule_score
    else:
        # The ML model is a supporting signal, not the sole decision-maker.
        final_score = round((rule_score * 0.70) + (model_score * 100 * 0.30))

    # Strong danger signals should not be hidden by a low model score.
    critical_signal = any(
        item["severity"] == "CRITICAL" for item in findings
    )

    if critical_signal:
        final_score = max(final_score, 85)

    if any(
        item["name"].startswith("Possible ")
        and item["name"].endswith(" demand")
        for item in findings
    ):
        final_score = max(final_score, 65)

    final_score = min(100, max(0, int(final_score)))

    if critical_signal or final_score >= 75:
        risk_level = "CRITICAL" if critical_signal else "HIGH"
    elif final_score >= 45:
        risk_level = "HIGH"
    elif final_score >= 20:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    advice = list(dict.fromkeys(item["advice"] for item in findings))

    if not advice:
        advice = [
            "No major warning pattern was detected by the current checks.",
            "Verify the company and internship through its official website.",
            "Never pay money or share OTPs, UPI PINs or passwords to obtain an internship.",
        ]

    positive_signals = []

    if not re.search(r"\b(fee|deposit|pay immediately|otp|upi pin)\b", message, re.I):
        positive_signals.append(
            "No obvious fee, deposit or credential request was detected."
        )

    if not re.search(r"\b(guaranteed selection|100% placement)\b", message, re.I):
        positive_signals.append(
            "No explicit guaranteed-selection claim was detected."
        )

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "model_score": model_score,
        "rule_score": rule_score,
        "reasons": findings,
        "advice": advice,
        "positive_signals": positive_signals,
        "model_available": model_score is not None,
    }