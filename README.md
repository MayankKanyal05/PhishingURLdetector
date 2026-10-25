import re
import ipaddress
from urllib.parse import urlparse, unquote

import streamlit as st

st.set_page_config(
        page_title="PhishGuard | URL Detector",
        page_icon="🛡️",
        layout="centered"
    )
SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "shorturl.at"
    }

SUSPICIOUS_WORDS = {
        "login",
        "signin",
        "verify",
        "verification",
        "password",
        "secure",
        "account",
        "update",
        "banking",
        "confirm",
        "wallet"
    }


    # ---------------- URL ANALYZER ----------------

def analyze_url(user_url):
        url = user_url.strip()
        findings = []
        score = 0

        if not url:
            return {
                "score": 0,
                "risk": "INVALID INPUT",
                "findings": ["Please enter a URL."]
            }

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url
        ):
            url = "http://" + url

        try:
            parsed = urlparse(url)

            if parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError(
                    "Only HTTP and HTTPS URLs are supported."
                )

            hostname = parsed.hostname

            if not hostname:
                raise ValueError("No valid hostname was found.")

            hostname = hostname.rstrip(".").lower()

            parsed.port

        except ValueError as error:
            return {
                "score": 0,
                "risk": "INVALID URL",
                "findings": [str(error)]
            }

        def flag(points, message):
            nonlocal score
            score += points
            findings.append(message)

        # 1. IP address used as hostname
        try:
            ipaddress.ip_address(hostname)
            flag(3, "The hostname is an IP address.")
        except ValueError:
            pass

        # 2. User information inside URL
        if parsed.username is not None or parsed.password is not None:
            flag(
                4,
                "User information appears before the hostname."
            )

        # 3. Unusually long URL
        if len(user_url) > 100:
            flag(2, "The URL is unusually long.")

        # 4. Many domain labels
        if len(hostname.split(".")) >= 5:
            flag(2, "The hostname has many domain labels.")

        # 5. Suspicious words
        decoded_text = unquote(
            hostname + parsed.path + " " + parsed.query
        ).lower()

        matched_words = sorted(
            word
            for word in SUSPICIOUS_WORDS
            if re.search(
                rf"\b{re.escape(word)}\b",
                decoded_text
            )
        )

        if matched_words:
            flag(
                2,
                "Potentially sensitive words: "
                + ", ".join(matched_words)
            )

        # 6. URL shortener
        if hostname in SHORTENERS:
            flag(2, "A known URL-shortening service is used.")

        # 7. At symbol
        if "@" in user_url:
            flag(3, "The URL contains '@', which can obscure its destination.")

        # 8. Encoded characters
        if "%" in user_url:
            flag(1, "The URL contains percent-encoded characters.")

        # 9. Backslashes
        if "\\" in user_url:
            flag(2, "The URL contains backslashes.")

        # 10. Multiple hyphens
        if hostname.count("-") >= 3:
            flag(2, "The hostname contains multiple hyphens.")

        # 11. Missing HTTPS
        if parsed.scheme.lower() != "https":
            flag(1, "The URL does not use HTTPS.")

        score = min(score, 10)

        if score >= 6:
            risk = "HIGH RISK"
        elif score >= 3:
            risk = "SUSPICIOUS"
        else:
            risk = "LOW RISK"

        if not findings:
            findings.append(
                "No warning signs from these checks were detected."
            )

        return {
            "score": score,
            "risk": risk,
            "findings": findings
        }


    # ---------------- FRONTEND DESIGN ----------------

st.title("PhishGuard")
st.caption("PYTHON CYBERSECURITY PROJECT")
st.markdown("## Phishing URL Detector")
st.write(
        "Analyze a URL for common phishing indicators "
        "using a Python-based detection engine."
    )

st.divider()

with st.container(border=True):
        st.subheader("Check a URL")

        with st.form("url_form"):
            user_url = st.text_input(
                "Enter URL",
                placeholder="https://example.com/login",
                max_chars=2048,
                help="Enter a URL as text. Do not open suspicious links."
            )

            submitted = st.form_submit_button(
                "Analyze URL",
                type="primary",
                use_container_width=True
            )

        st.caption(
            "Analysis runs locally. Do not enter passwords or other secrets."
        )


    # ---------------- DISPLAY RESULTS ----------------

if submitted:
        if not user_url.strip():
            st.warning("Please enter a URL first.")

        else:
            result = analyze_url(user_url)

            st.divider()
            st.subheader("Analysis Report")

            risk = result["risk"]
            score = result["score"]

            if risk == "INVALID URL" or risk == "INVALID INPUT":
                st.error(risk)
                st.write(result["findings"][0])

            else:
                col1, col2 = st.columns(2)

                with col1:
                    st.metric("Risk Score", f"{score}/10")

                with col2:
                    st.metric("Risk Classification", risk)

                st.progress(score / 10)

                if risk == "HIGH RISK":
                    st.error(
                        "⚠️ Multiple warning signs detected. "
                        "Avoid opening the link unless you can "
                        "independently verify it."
                    )

                elif risk == "SUSPICIOUS":
                    st.warning(
                        "Some warning signs were detected. "
                        "Verify the destination before trusting it."
                    )

                else:
                    st.success(
                        "Few or no warning signs were detected "
                        "by these basic checks."
                    )

                st.subheader("Detected Indicators")

                for finding in result["findings"]:
                    st.markdown(f"- {finding}")

                with st.expander("How is the score calculated?"):
                    st.write(
                        "The detector assigns points to predefined "
                        "URL indicators. The total is capped at 10."
                    )
                    st.write(
                        "0–2: Low risk | 3–5: Suspicious | 6–10: High risk"
                    )

st.divider()

st.subheader("About this project")

col1, col2, col3 = st.columns(3)

with col1:
        st.markdown("**URL Analysis**")
        st.caption("Inspect URL structure and patterns.")

with col2:
        st.markdown("**Risk Scoring**")
        st.caption("Calculate a heuristic score from 0 to 10.")

with col3:
        st.markdown("**Awareness**")
        st.caption("Learn to recognize possible phishing signs.")
