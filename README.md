# 🔐 AI Cybersecurity Advisor

![License](https://img.shields.io/badge/License-MIT-blue.svg)

AI Cybersecurity Advisor is a smart web-based assistant that helps users analyze website URLs, check for password breaches, and receive AI-powered cybersecurity advice. Built using **OpenAI GPT**, **VirusTotal**, and **Have I Been Pwned (HIBP)** APIs, it provides intelligent and real-time threat insights to help individuals stay safe online.

---

## 🚀 Features

- 🧠 GPT-powered assistant for cybersecurity queries
- 🛡️ Checks if passwords are compromised using HIBP API
- 🔍 Scans URLs and files for threats via VirusTotal API
- 🌐 Simple HTML/CSS/JS frontend with Python Flask backend
- 🧪 Security test script and test report included

---

## 📁 Project Structure

project/
├── backend/
│ ├── app.py # Flask backend
│ ├── cybersecurity_agent.py # GPT, VirusTotal, HIBP logic
│ └── .env # API keys and config
├── frontend/
│ ├── index.html # Main UI
│ ├── popup.html # Optional popup
│ ├── popup.js, script.js # JS logic
│ └── styles.css # Styles
├── test_report.pdf # Testing report
├── test_security.py # Test script
├── requirements.txt # Python dependencies
└── README.md # Project documentation

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/Hanzala095/ai-cybersecurity-advisor.git
cd ai-cybersecurity-advisor
2. Create and Activate Virtual Environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install Dependencies
pip install -r requirements.txt

4. Configure Environment Variables
Create a .env file in the backend/ directory and add your API keys:

OPENAI_API_KEY=your_openai_key
VIRUSTOTAL_API_KEY=your_virustotal_key
HIBP_API_KEY=your_hibp_key

5. Run the App
Navigate to the backend directory and start the Flask app:
cd backend
python app.py
The app should now be running locally. You can access it via http://127.0.0.1:5000/.