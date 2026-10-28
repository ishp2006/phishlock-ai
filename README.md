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

## Deploying to Render (Free Tier)

This repository is configured for direct deployment on [Render](https://render.com) as a full-stack Web Service (serving both the Flask API and frontend dashboard together).

### Method 1: Render Blueprints (Recommended — 1-Click Setup)
1. Push this repository to your GitHub account.
2. In Render Dashboard, click **New +** > **Blueprint**.
3. Select your repository. Render will automatically read `render.yaml`, configure Python, install dependencies, and launch with Gunicorn.
4. Click **Apply**.

### Method 2: Manual Web Service Setup
1. Push this repository to GitHub.
2. In Render Dashboard, click **New +** > **Web Service**.
3. Connect your GitHub repository.
4. Fill in the service settings:
   - **Name:** `phishlock-ai`
   - **Environment:** `Python 3`
   - **Branch:** `main`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Plan:** `Free`
5. Click **Create Web Service**.

Once deployed, Render provides an HTTPS URL (e.g. `https://phishlock-ai.onrender.com`) where your full dashboard and APIs are immediately accessible.

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