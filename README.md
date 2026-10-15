# EmailShield-AI 🛡️

**Autonomous AI-Powered Email Phishing & Social Engineering Intelligence Platform**

EmailShield-AI is a standalone, deployment-ready cybersecurity application that inspects suspicious incoming email headers, bodies, and embedded links. It synthesizes deep rule-based heuristic signal extraction with **Google Gemini Generative AI** (`gemini-2.5-flash`), backed by **TiDB Cloud Serverless MySQL** and **Resend** transactional notification services.

---

## 🚀 Key Features

* **Advanced Email Body & Header Triage**: Analyzes raw email bodies, optional subject lines, and sender addresses without executing scripts, rendering active HTML, or opening malicious URLs.
* **Dual-Tier Threat Engine**:
  * **Heuristic Signal Extractor**: Analyzes coercion phrases, urgent deadlines, credential harvesting patterns, financial transaction demands, and raw IP/shortened URLs.
  * **Google Gemini AI Reasoning**: Performs zero-shot cognitive threat evaluation, providing calibrated risk scoring (0–100), key indicators, and defensive advisories.
  * **Transparent Fallback Mode**: If Gemini is unreachable or unconfigured, the system automatically runs on its local heuristic engine and clearly notes this in the results.
* **Calibrated Risk Scoring (0–100)**:
  * `0 – 24` : **Likely Safe** (Standard communication pattern, no deceptive links or coercion).
  * `25 – 64`: **Suspicious** (Minor anomalies, unverified sender, or mild pressure).
  * `65 – 100`: **Phishing** (Deceptive domain spoofing, credential harvesting, or wire fraud).
* **Advisory Safety Policy**: Never claims an email is "definitively safe" — automated AI analysis is clearly flagged as an advisory tool.
* **TiDB Cloud Serverless Persistence**: Stores user accounts and audit logs with connection pooling, TLS/SSL encryption, and local SQLite development fallback.
* **Strict Per-User Telemetry Isolation**: Each user can only access their own scan history.
* **Resend Integration**: Sends executive threat summaries and password-reset OTP verification codes directly to verified inboxes.
* **Data Privacy First**: Avoids storing sensitive raw email bodies in the database by default (stores only calculated findings, scores, and short previews).

---

## 📂 Project Structure

```text
EmailShield-AI/
├── app/
│   ├── __init__.py
│   ├── config.py              # Environment configuration & typed settings
│   ├── database.py            # TiDB Cloud MySQL pool with SQLite fallback
│   ├── auth.py                # Password hashing (bcrypt) & user management
│   ├── analyzer.py            # Phishing analyzer & Gemini AI integration
│   ├── notifications.py       # Resend email dispatcher (summaries & OTP)
│   ├── models.py              # Data structures & schemas
│   └── views/
│       ├── __init__.py
│       ├── layout.py          # Dark navy cyber theme & navigation header
│       ├── auth_view.py       # Login, Register & OTP password reset
│       ├── dashboard_view.py  # Overview stats cards & threat primer
│       ├── analyzer_view.py   # Interactive email analysis console
│       ├── history_view.py    # Isolated user logs & detail inspect modal
│       └── settings_view.py   # System health, DB diagnostics & logout
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py       # Heuristics, Gemini mocking & input limits
│   ├── test_database.py       # DB schema, user isolation & error handling
│   ├── test_notifications.py  # Resend OTP & report dispatch tests
│   └── test_app.py            # Health check endpoint & routing tests
├── scripts/
│   └── init_db.py             # Standalone DB schema migration script
├── main.py                    # Entry point & FastAPI health endpoint
├── requirements.txt           # Production dependencies
├── render.yaml                # Render Blueprint deployment manifest
├── Procfile                   # Process file for Render web service
├── .env.example               # Configuration template with placeholders
├── .gitignore                 # Secret, cache, and artifact exclusions
└── README.md                  # Comprehensive setup & deployment guide
```

---

## 💻 Local Setup Instructions (Windows)

### 1. Clone or Extract the Project
Extract `EmailShield-AI-Ready.zip` to your desired folder. Open **PowerShell** or **Command Prompt** inside the `EmailShield-AI` folder:

```powershell
cd EmailShield-AI
```

### 2. Create and Activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

*(If script execution is disabled in PowerShell, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env`:

```powershell
Copy-Item .env.example .env
```

Open `.env` in any text editor and configure your credentials (see next section).

### 5. Initialize Database Schema
```powershell
python scripts/init_db.py
```

### 6. Start the Application
```powershell
python main.py
```

Open your browser and navigate to:
👉 **`http://localhost:8080`**

---

## 🔑 Environment Variables Reference

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `HOST` | Bind host address | `0.0.0.0` |
| `PORT` | Bind port number | `8080` (or dynamically set by Render) |
| `SECRET_KEY` | Secret key for encrypted user sessions | Random 32+ character string |
| `GEMINI_API_KEY` | Google Gemini AI API key | `AIzaSy...` (from Google AI Studio) |
| `GEMINI_MODEL` | Gemini model variant | `gemini-2.5-flash` |
| `TIDB_HOST` | TiDB Cloud Gateway Host | `gateway01.ap-southeast-1.prod.aws.tidbcloud.com` |
| `TIDB_PORT` | TiDB Cloud MySQL Port | `4000` |
| `TIDB_USER` | TiDB Cloud Username | `<cluster-prefix>.root` |
| `TIDB_PASSWORD` | TiDB Cloud Database Password | Your cluster root password |
| `TIDB_DATABASE` | TiDB Database Name | `emailshield` (or `test`) |
| `TIDB_SSL_MODE` | SSL Mode for TLS connection | `VERIFY_IDENTITY` |
| `USE_SQLITE_FALLBACK`| Enable local SQLite if TiDB is offline | `true` |
| `RESEND_API_KEY` | Resend API Key | `re_...` (from resend.com) |
| `RESEND_FROM_EMAIL` | Verified sending email in Resend | `onboarding@resend.dev` |
| `STORE_EMAIL_BODY` | Privacy toggle for raw email bodies | `false` |
| `MAX_EMAIL_SIZE_BYTES`| Max size of submitted email text | `51200` (50 KB) |

---

## ☁️ Connecting to TiDB Cloud (Step-by-Step)

1. **Sign Up / Log In**: Visit [https://tidbcloud.com](https://tidbcloud.com) and sign in.
2. **Create a Free Cluster**:
   * Click **Create Cluster** $\rightarrow$ Select **Serverless** (Free Tier).
   * Choose your preferred region (e.g., `AWS / us-east-1` or `ap-southeast-1`).
   * Enter a cluster name (e.g., `emailshield-cluster`) and click **Create**.
3. **Set Root Password**:
   * During cluster creation, generate a strong root password. Copy this password into `TIDB_PASSWORD`.
4. **Obtain Connection Details**:
   * Click **Connect** on your cluster dashboard.
   * Under **Connection Type**, select **Standard Connection (MySQL Client)**.
   * Note the Host (e.g. `gateway01.us-east-1.prod.aws.tidbcloud.com`), Port (`4000`), and User (e.g. `4abcdefgh.root`).
5. **Populate `.env`**:
   ```env
   TIDB_HOST=gateway01.us-east-1.prod.aws.tidbcloud.com
   TIDB_PORT=4000
   TIDB_USER=4abcdefgh.root
   TIDB_PASSWORD=YourCopiedPassword
   TIDB_DATABASE=test
   TIDB_SSL_MODE=VERIFY_IDENTITY
   ```
6. **Run Schema Setup**:
   ```powershell
   python scripts/init_db.py
   ```
   *The script creates the `users` and `email_analyses` tables with foreign keys and indexes.*

---

## 🤖 Obtaining a Google Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/).
2. Sign in with your Google account.
3. Click **Get API key** $\rightarrow$ **Create API key in new project**.
4. Copy the generated key and set it in `.env`:
   ```env
   GEMINI_API_KEY=AIzaSyYourGeneratedGeminiKey
   GEMINI_MODEL=gemini-2.5-flash
   ```

---

## 📬 Configuring Resend Email Notifications

1. Sign up at [https://resend.com](https://resend.com).
2. Go to **API Keys** $\rightarrow$ **Create API Key**. Give it "Full Access" or "Sending access".
3. Copy the key and set:
   ```env
   RESEND_API_KEY=re_1234567890abcdef
   ```
4. For testing without a custom domain, you can use Resend's default test sender:
   ```env
   RESEND_FROM_EMAIL=onboarding@resend.dev
   ```
   *(Note: Free test accounts on Resend can send emails to the email address registered with your Resend account. To send to any recipient, verify your custom domain in Resend Domains).*

---

## 🚀 Deploying to Render

This project includes a native `render.yaml` Blueprint and `Procfile`.

### Method A: Deploy via Blueprint (Recommended)
1. Push this project folder to a GitHub repository (ensure `.env` is NOT committed).
2. Log in to [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** $\rightarrow$ **Blueprint**.
4. Connect your GitHub repository.
5. Render reads `render.yaml` and prepares the web service.
6. Under **Environment Variables**, fill in your secret values:
   * `GEMINI_API_KEY`
   * `TIDB_HOST`
   * `TIDB_USER`
   * `TIDB_PASSWORD`
   * `TIDB_DATABASE`
   * `RESEND_API_KEY`
7. Click **Apply**. Render will automatically run `pip install -r requirements.txt` and start `python main.py`.

### Method B: Manual Web Service on Render
* **Runtime**: Python 3
* **Build Command**: `pip install -r requirements.txt`
* **Start Command**: `python main.py`
* **Health Check Path**: `/health`
* **Environment Variables**: Add the variables listed in the Reference table above.

---

## 🧪 Running Automated Tests

Run the full test suite with `pytest`:

```powershell
python -m pytest tests -v
```

All 20 test cases cover:
* Input validation (empty, oversized, malformed input).
* Heuristic threat scoring (urgency, credential harvesting, financial fraud, link parsing).
* Gemini AI mocking and verified fallback behavior.
* Database initialization, persistence, and strict per-user isolation.
* Database connection failure resilience.
* Resend report and OTP delivery.
* `/health` monitoring endpoint.

---

## 🛡️ Security & Privacy Notice

* **No Script Execution**: Email content is parsed strictly as passive text. No hyperlinks are opened and no embedded scripts or objects are executed during analysis.
* **Privacy Conscious**: By default (`STORE_EMAIL_BODY=false`), raw email bodies are never stored in the database.
* **Advisory Disclaimer**: Automated AI systems can produce false positives and false negatives. Always verify suspicious communications through out-of-band channels.
