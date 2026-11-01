# Streamlit Community Cloud Deployment Guide 🚀
## Incident Detection for DNS Tunneling Attacks (DNS Armor)

This guide provides step-by-step instructions to deploy your **DNS Armor** SOC application online for **free** with a public HTTPS URL (e.g., `https://dns-armor.streamlit.app`).

---

## 📋 Prerequisites
1. A free **GitHub account** ([github.com](https://github.com/))
2. A free **Streamlit Community Cloud account** ([share.streamlit.io](https://share.streamlit.io/)) linked to your GitHub.

---

## 🚀 Step 1: Create a GitHub Repository

1. Open your browser and go to [github.com/new](https://github.com/new).
2. Set the repository name to:
   ```
   dns-tunnel-detector
   ```
3. Set visibility to **Public** (required for free Streamlit Community Cloud hosting).
4. Do **not** initialize with a README, .gitignore, or license (we already created them locally).
5. Click **"Create repository"**.

---

## 💻 Step 2: Push Your Local Code to GitHub

Open PowerShell in the project directory:
`C:\Users\singh\.gemini\antigravity\scratch\dns-tunnel-detector`

Run the following two commands (replace `<YOUR_GITHUB_USERNAME>` with your actual GitHub username):

```powershell
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/dns-tunnel-detector.git
git push -u origin main
```

*(If prompted, sign in via browser or personal access token to authorize git push).*

---

## 🌐 Step 3: Deploy on Streamlit Community Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io/) and click **"Sign in with GitHub"**.
2. Click the **"New app"** (or **"Create app"**) button.
3. Fill in the deployment form:
   - **Repository:** `<YOUR_GITHUB_USERNAME>/dns-tunnel-detector`
   - **Branch:** `main`
   - **Main file path:** `app.py` *(or `dashboard/app.py`)*
   - **App URL:** (Optional) Customize your subdomain, e.g., `dns-armor-soc` or `dns-tunnel-detection`
4. Click **"Deploy!"** 🎈

---

## ⚙️ What Happens Automatically
- Streamlit Cloud builds a secure Linux container.
- It detects `requirements.txt` and installs all dependencies (`scikit-learn`, `scapy`, `plotly`, `pyotp`, `qrcode`, etc.).
- It applies your custom theme settings from `.streamlit/config.toml` (dark obsidian cyber theme).
- Within ~1–2 minutes, your live web application will be live at `https://<your-subdomain>.streamlit.app` with an active SSL certificate!

---

## 🔐 Zero-Trust Login Credentials on Live Deployment
Your pre-configured evaluator roles work seamlessly in the cloud:

| Role | Username / Email | Password | Base32 Secret |
| :--- | :--- | :--- | :--- |
| **SOC Tier-2 Analyst** | `analyst@soc.corp` | `CyberDefense@2026` | `JBSWY3DPEHPK3PXP` |
| **CISO / Red Team Admin** | `admin@soc.corp` | `RootAdmin@2026` | `KRMUY4TFOJQXEZ3T` |

*Evaluator tip: The **"⚡ One-Click Live OTP"** button allows anyone viewing your cloud app to test the MFA verification instantly without needing a mobile authenticator app.*

---

## 🐳 Alternative: Docker Deployment
If you ever want to run the project in a self-hosted cloud container (AWS EC2, Google Cloud Run, DigitalOcean, or Azure):

```bash
docker-compose up --build -d
```
The app will be available at `http://<SERVER_IP>:8501`.
