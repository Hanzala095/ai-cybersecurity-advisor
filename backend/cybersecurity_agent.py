from langchain.agents import AgentExecutor, Tool, create_react_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain import hub
import requests
import os
import json
from dotenv import load_dotenv
from collections import defaultdict
import time

# Disable LangSmith if not configured
os.environ["LANGCHAIN_TRACING_V2"] = "false"

load_dotenv()

# API Keys setup
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

# Initialize LLM
llm = ChatOpenAI(model="gpt-4", temperature=0)

# Security statistics
security_stats = {
    'total_scans': 0,
    'threats_blocked': defaultdict(int),
    'last_scan': None
}

def analyze_email_content(email):
    """Enhanced phishing email detection"""
    prompt = f"""Analyze this email for phishing indicators. Return JSON with:
    - risk_score (0-100)
    - is_phishing (boolean)
    - reasons (list)
    - sender_analysis (str)
    - link_analysis (str)

    Email Content:
    {email}

    Check for:
    1. Suspicious sender address (e.g., not matching claimed organization)
    2. Urgent/threatening language
    3. Mismatched links (hover vs displayed)
    4. Requests for sensitive information
    5. Poor grammar/spelling
    6. Unusual attachments
    """
    
    response = llm.invoke(prompt)
    try:
        result = json.loads(response)
        if result.get('is_phishing'):
            update_stats('phishing_email')
        return result
    except:
        return {
            "risk_score": 80,
            "is_phishing": True,
            "reasons": ["Failed to analyze - assume phishing"],
            "sender_analysis": "Unknown",
            "link_analysis": "Unknown"
        }
    
def update_stats(threat_type=None):
    security_stats['total_scans'] += 1
    security_stats['last_scan'] = time.time()
    if threat_type:
        security_stats['threats_blocked'][threat_type] += 1

def check_phishing_url(url):
    """Check URL using VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url}", 
            headers=headers
        )
        result = response.json()
        malicious = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
        if malicious:
            update_stats('phishing')
        return {"is_malicious": malicious, "details": result}
    except Exception as e:
        return {"error": str(e)}

def check_password_breach(password):
    """Enhanced password check with local common passwords"""
    COMMON_PASSWORDS = {
        "123456", "password", "123456789", 
        "12345", "qwerty", "admin", "welcome"
    }
    
    # First check against local common passwords
    if password in COMMON_PASSWORDS:
        return {
            "is_breached": True,
            "breach_count": ">1 million",
            "reason": "Extremely common password"
        }
    
    # Then check HIBP API
    headers = {"hibp-api-key": HIBP_API_KEY}
    try:
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/pwnedpassword/{password}",
            headers=headers
        )
        if response.status_code == 200:
            return {
                "is_breached": True,
                "breach_count": int(response.text),
                "reason": "Found in breached databases"
            }
        return {"is_breached": False}
    except Exception as e:
        return {
            "is_breached": None,
            "error": str(e),
            "recommendation": "Assume password may be compromised"
        }

def analyze_content(content, content_type):
    """Unified content analysis"""
    prompt = f"""Analyze this {content_type} content for security risks:
    {content}
    
    Return JSON with:
    - risk_score (0-100)
    - is_threat (boolean)
    - threats (list)
    - recommendations (list)
    """
    
    try:
        response = llm.invoke(prompt)
        result = json.loads(response)
        if result.get('is_threat'):
            update_stats(content_type)
        return result
    except Exception as e:
        return {
            "error": str(e),
            "risk_score": 50,
            "is_threat": False,
            "threats": ["Analysis failed"],
            "recommendations": ["Manual review recommended"]
        }

# Create tools
tools = [
    Tool(
        name="url_scanner",
        func=lambda url: check_phishing_url(url),
        description="URL security analysis"
    ),
    Tool(
        name="password_checker",
        func=lambda pwd: check_password_breach(pwd),
        description="Password breach check"
    ),
    Tool(
        name="content_analyzer",
        func=lambda content: analyze_content(content[0], content[1]),
        description="Content security analysis"
    )
]

# Create agent
prompt = hub.pull("hwchase17/react-chat")
agent = create_react_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

def run_advisor(query):
    response = agent_executor.invoke({"input": query})
    return response["output"]

def get_stats():
    return security_stats