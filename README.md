# PhishLock AI 🛡️

### Rule-Based Phishing Detection System

PhishLock AI is a cybersecurity project designed to help users identify potentially suspicious URLs and messages through rule-based heuristic analysis.

The system evaluates input patterns and provides a risk score, risk classification, security indicators, and recommendations to help users understand possible warning signs.

## Problem Statement

Phishing attacks use deceptive links and messages to trick people into sharing sensitive information, including passwords and banking details. Users may not always recognize suspicious patterns before interacting with such content.

PhishLock AI aims to help users recognize these warning signs through an accessible web interface.

## Features

* **URL Analysis:** Analyze URL text using predefined heuristic rules.
* **Message Analysis:** Check messages for potentially suspicious language and patterns.
* **Risk Assessment:** Display a risk score and classification.
* **Security Indicators:** Explain warning signs identified during analysis.
* **Recommendations:** Provide basic security guidance.
* **Web Interface:** Submit inputs and view analysis results in one place.

## Technology Stack

| Technology | Purpose                                               |
| ---------- | ----------------------------------------------------- |
| HTML       | Page structure                                        |
| CSS        | User interface styling                                |
| JavaScript | User interactions and API requests                    |
| Python     | Backend analysis logic                                |
| Flask      | Backend server and API endpoints                      |
| SQLite     | Database component for potential scan-history storage |

## How It Works

1. The user submits a URL or message.
2. The frontend sends the input to the Flask backend.
3. The backend applies predefined heuristic rules.
4. The system calculates a risk score and classification.
5. The result includes identified indicators and recommendations.

**Workflow:**

User Input → Web Interface → Flask API → Rule-Based Analysis → Risk Assessment → Results

## Run Locally

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd phishlock-ai
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Install dependencies

```bash
py -m pip install -r requirements.txt
```

### 3. Start the Flask server

```bash
py app.py
```

### 4. Open the application

Open this address in your browser:

http://127.0.0.1:5000

## Deployment Architecture

PhishLock AI is configured to run in two deployment modes:
1. **Frontend on Vercel + Backend on Render** (Decoupled Cloud Architecture)
2. **Unified on Render** (Single Full-Stack Web Service)

---

### Mode 1: Frontend on Vercel + Backend on Render

#### Step A: Deploy Backend to Render (Free Web Service)
1. Push this repository to GitHub.
2. In [Render Dashboard](https://dashboard.render.com), click **New +** > **Web Service**.
3. Select your repository:
   - **Name:** `phishlock-ai-api`
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Plan:** `Free`
4. Click **Create Web Service**.
5. Copy your live Render URL (e.g., `https://phishlock-ai-api.onrender.com`).

#### Step B: Deploy Frontend to Vercel
1. Log in to [Vercel](https://vercel.com) and click **Add New...** > **Project**.
2. Import your GitHub repository (`phishlock-ai`).
3. Leave **Framework Preset** as **Other** (Root directory: `./`).
4. Click **Deploy**.
5. Vercel will deploy your static files (`index.html`, `style.css`, `script.js`).

#### Step C: Connect Frontend to Backend
- Update `DEFAULT_RENDER_BACKEND_URL` in `script.js` or `vercel.json` with your live Render backend URL.
- CORS is pre-configured on Flask to accept cross-origin requests from any Vercel domain (`*.vercel.app`).
- *Note:* Render's free tier spins down after inactivity. When you initiate the first scan after sleep, give it ~30 seconds to wake up.

---

### Mode 2: Unified Deployment on Render (Alternative)
If you prefer a single service without configuring cross-service URLs:
1. In Render Dashboard, click **New +** > **Blueprint**.
2. Select your repository. Render uses `render.yaml` to deploy both frontend and backend under one URL automatically.

---

## API Endpoints

| Method | Endpoint               | Purpose                     |
| ------ | ---------------------- | --------------------------- |
| GET    | `/api/health`          | Check backend health        |
| POST   | `/api/analyze-url`     | Analyze a submitted URL     |
| POST   | `/api/analyze-message` | Analyze a submitted message |

The analysis endpoints accept JSON input and return structured results. Their behavior should be verified against the current backend implementation.

## Project Scope and Limitations

* The current analysis uses predefined rules and heuristic checks.
* The project does not use a trained AI model for its current analysis.
* The backend does not open submitted URLs or verify the live contents of the websites.
* HTTPS alone does not guarantee that a website is trustworthy.
* A low-risk result is not proof that a URL or message is safe.
* Results are indicative and should not replace professional security checks.

## Future Improvements

* Improve detection rules and testing coverage.
* Verify and implement persistent scan-history storage.
* Integrate trusted threat-intelligence sources.
* Explore machine-learning-based phishing detection.
* Improve the user interface and error handling.

## Project Status

PhishLock AI is a cybersecurity prototype under development. The URL analysis API has been tested locally. Additional feature testing and deployment verification are part of the development process.

## Disclaimer

This project is intended for educational and cybersecurity awareness purposes. Analysis results may be incomplete or inaccurate. Always verify suspicious links independently and avoid submitting passwords or other sensitive information.

---

Developed as a cybersecurity project.
Author 
ISHA PAL