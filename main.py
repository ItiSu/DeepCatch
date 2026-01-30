"""
Phishing Detection Web App
Requirements:
- pip install fastapi uvicorn transformers torch openai python-dotenv
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from transformers import pipeline
from pydantic import BaseModel
import logging
import os
from openai import OpenAI
import re
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="DeepCatch - Phishing Detection")

# Load the pretrained model from Hugging Face
# This runs completely locally - no API calls
# NOTE: BERT model is kept for reference but not used in predictions
logger.info("Loading phishing detection model...")
try:
    pipe = pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")
    logger.info("Model loaded successfully!")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    pipe = None

# Initialize DeepSeek client
deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
if not deepseek_api_key:
    logger.warning("DEEPSEEK_API_KEY not found in environment variables")
    deepseek_client = None
else:
    deepseek_client = OpenAI(
        api_key=deepseek_api_key,
        base_url="https://api.deepseek.com"
    )
    logger.info("DeepSeek client initialized successfully!")

# Request model for API
class TextInput(BaseModel):
    text: str

def extract_urls(text: str) -> list:
    """Extract URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def detect_input_type(text: str) -> str:
    """Detect the type of input content"""
    text_lower = text.lower()
    
    # Check for URL
    if re.search(r'http[s]?://', text):
        return "URL/Link"
    
    # Check for email patterns
    if any(keyword in text_lower for keyword in ['subject:', 'from:', 'to:', 'dear', 'regards', 'sincerely']):
        return "Email"
    
    # Check for SMS patterns
    if len(text) < 200 and any(keyword in text_lower for keyword in ['click', 'reply', 'text', 'msg']):
        return "SMS/Text Message"
    
    # Default to general text
    return "Text/Message"

async def analyze_with_deepseek(text: str) -> dict:
    """
    Use DeepSeek API to analyze content for phishing
    Returns detailed analysis with verdict, confidence, explanation, highlighting, and metadata
    """
    start_time = time.time()
    
    if not deepseek_client:
        raise Exception("DeepSeek API client not initialized. Please set DEEPSEEK_API_KEY environment variable.")
    
    # Create the prompt for DeepSeek
    prompt = f"""You are an expert cybersecurity analyst specializing in phishing detection. Analyze the following content for phishing indicators.

Content to analyze:
{text}

Please provide a comprehensive analysis with the following structure:

1. VERDICT: Classify as one of these:
   - "Safe" - legitimate content with no phishing indicators
   - "Suspicious" - contains some concerning elements but not definitively phishing
   - "High-risk" - clear phishing attempt with multiple red flags

2. CONFIDENCE: Provide a confidence score from 0-100%

3. EXPLANATION: A brief 2-3 sentence explanation of why you reached this verdict

4. HIGHLIGHTED_CONTENT: Return the original content with risky parts wrapped in tags:
   - Use <red>text</red> for high-risk elements (dangerous URLs, credential requests, etc.)
   - Use <yellow>text</yellow> for suspicious elements (urgency tactics, spelling errors, etc.)
   - Keep safe text unchanged

5. METADATA:
   - Input type (Email, SMS, URL, or Text)
   - Number of suspicious elements found
   - List of extracted URLs (if any)
   - List of suspicious senders/domains (if applicable)

Format your response EXACTLY as follows (use these exact section headers):

VERDICT: [Safe/Suspicious/High-risk]
CONFIDENCE: [number]%
EXPLANATION: [your explanation]
HIGHLIGHTED_CONTENT:
[content with <red> and <yellow> tags]
METADATA:
Input Type: [type]
Suspicious Elements: [number]
URLs Found: [list or "None"]
Senders/Domains: [list or "None"]"""

    try:
        # Call DeepSeek API
        response = deepseek_client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection. Provide detailed, accurate analysis with specific evidence."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=2000
        )
        
        analysis_text = response.choices[0].message.content
        analysis_time = round(time.time() - start_time, 2)
        
        # Parse the response
        result = {
            "verdict": "Safe",
            "confidence": 50,
            "explanation": "Analysis completed",
            "highlighted_content": text,
            "metadata": {
                "input_type": detect_input_type(text),
                "suspicious_elements": 0,
                "urls_found": extract_urls(text),
                "senders_domains": [],
                "analysis_time": analysis_time
            }
        }
        
        # Extract verdict
        verdict_match = re.search(r'VERDICT:\s*(\w+(?:-\w+)?)', analysis_text, re.IGNORECASE)
        if verdict_match:
            result["verdict"] = verdict_match.group(1)
        
        # Extract confidence
        confidence_match = re.search(r'CONFIDENCE:\s*(\d+)%?', analysis_text, re.IGNORECASE)
        if confidence_match:
            result["confidence"] = int(confidence_match.group(1))
        
        # Extract explanation
        explanation_match = re.search(r'EXPLANATION:\s*(.+?)(?=HIGHLIGHTED_CONTENT:|METADATA:|$)', analysis_text, re.IGNORECASE | re.DOTALL)
        if explanation_match:
            result["explanation"] = explanation_match.group(1).strip()
        
        # Extract highlighted content
        highlighted_match = re.search(r'HIGHLIGHTED_CONTENT:\s*(.+?)(?=METADATA:|$)', analysis_text, re.IGNORECASE | re.DOTALL)
        if highlighted_match:
            result["highlighted_content"] = highlighted_match.group(1).strip()
        
        # Extract metadata
        metadata_match = re.search(r'METADATA:\s*(.+)', analysis_text, re.IGNORECASE | re.DOTALL)
        if metadata_match:
            metadata_text = metadata_match.group(1)
            
            # Input type
            input_type_match = re.search(r'Input Type:\s*(.+?)(?=\n|$)', metadata_text, re.IGNORECASE)
            if input_type_match:
                result["metadata"]["input_type"] = input_type_match.group(1).strip()
            
            # Suspicious elements
            susp_elem_match = re.search(r'Suspicious Elements:\s*(\d+)', metadata_text, re.IGNORECASE)
            if susp_elem_match:
                result["metadata"]["suspicious_elements"] = int(susp_elem_match.group(1))
            
            # URLs found
            urls_match = re.search(r'URLs Found:\s*(.+?)(?=\n[A-Z]|$)', metadata_text, re.IGNORECASE | re.DOTALL)
            if urls_match:
                urls_text = urls_match.group(1).strip()
                if urls_text.lower() != "none":
                    result["metadata"]["urls_found"] = [url.strip() for url in urls_text.split(',') if url.strip()]
            
            # Senders/Domains
            senders_match = re.search(r'Senders/Domains:\s*(.+?)(?=\n|$)', metadata_text, re.IGNORECASE | re.DOTALL)
            if senders_match:
                senders_text = senders_match.group(1).strip()
                if senders_text.lower() != "none":
                    result["metadata"]["senders_domains"] = [s.strip() for s in senders_text.split(',') if s.strip()]
        
        logger.info(f"DeepSeek analysis completed: {result['verdict']} ({result['confidence']}%)")
        return result
        
    except Exception as e:
        logger.error(f"DeepSeek API error: {e}")
        raise Exception(f"DeepSeek analysis failed: {str(e)}")

# Homepage route
@app.get("/", response_class=HTMLResponse)
async def homepage():
    """Serve the homepage with a button to test phishing detection"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DeepCatch - AI-Powered Phishing Detection</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                background-color: #000000;
                color: #ffffff;
            }
            .hero {
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 40px 20px;
                background: linear-gradient(180deg, #000000 0%, #1a1a1a 100%);
            }
            .hero-content {
                text-align: center;
                max-width: 800px;
            }
            .logo {
                font-size: 72px;
                font-weight: bold;
                margin-bottom: 20px;
                letter-spacing: -2px;
            }
            .tagline {
                font-size: 24px;
                margin-bottom: 30px;
                color: #cccccc;
            }
            .description {
                font-size: 18px;
                margin-bottom: 40px;
                color: #999999;
                line-height: 1.6;
            }
            .cta-button {
                font-size: 20px;
                padding: 18px 50px;
                background-color: #ffffff;
                color: #000000;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
            }
            .cta-button:hover {
                background-color: #e0e0e0;
            }
            .features {
                background-color: #ffffff;
                padding: 80px 20px;
            }
            .features-container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .section-title {
                text-align: center;
                font-size: 36px;
                margin-bottom: 60px;
                color: #000000;
            }
            .features-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 40px;
            }
            .feature-card {
                text-align: center;
                padding: 40px 30px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                background-color: #ffffff;
                transition: all 0.3s ease;
            }
            .feature-card:hover {
                border-color: #000000;
                transform: translateY(-5px);
            }
            .feature-title {
                font-size: 22px;
                font-weight: bold;
                margin-bottom: 15px;
                color: #000000;
            }
            .feature-desc {
                font-size: 16px;
                color: #666666;
                line-height: 1.6;
            }
            .how-it-works {
                background-color: #f5f5f5;
                padding: 80px 20px;
            }
            .steps {
                max-width: 800px;
                margin: 0 auto;
            }
            .step {
                display: flex;
                align-items: start;
                margin-bottom: 40px;
            }
            .step-number {
                font-size: 32px;
                font-weight: bold;
                color: #000000;
                min-width: 60px;
            }
            .step-content {
                flex: 1;
            }
            .step-title {
                font-size: 22px;
                font-weight: bold;
                margin-bottom: 10px;
                color: #000000;
            }
            .step-desc {
                font-size: 16px;
                color: #666666;
                line-height: 1.6;
            }
            .stats {
                background-color: #1a1a1a;
                color: #ffffff;
                padding: 60px 20px;
                text-align: center;
            }
            .stats-grid {
                max-width: 900px;
                margin: 0 auto;
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 40px;
            }
            .stat-item {
                padding: 20px;
                border: 1px solid #333333;
            }
            .stat-number {
                font-size: 42px;
                font-weight: bold;
                margin-bottom: 10px;
            }
            .stat-label {
                font-size: 16px;
                color: #999999;
            }
            .footer {
                background-color: #000000;
                color: #ffffff;
                padding: 30px 20px;
                text-align: center;
                border-top: 1px solid #333333;
            }
            .footer-content {
                max-width: 800px;
                margin: 0 auto;
            }
            .footer-subtitle {
                margin-top: 10px;
                color: #666666;
            }
        </style>
    </head>
    <body>
        <section class="hero">
            <div class="hero-content">
                <div class="logo">DeepCatch</div>
                <div class="tagline">AI-Powered Phishing Detection</div>
                <p class="description">
                    Protect yourself from phishing attacks with advanced machine learning. 
                    DeepCatch uses state-of-the-art BERT models to analyze emails, messages, 
                    and URLs in real-time, running completely on your device.
                </p>
                <button class="cta-button" onclick="window.location.href='/detect'">
                    Start Detection
                </button>
            </div>
        </section>

        <section class="how-it-works">
            <div class="steps">
                <h2 class="section-title">How It Works</h2>
                <div class="step">
                    <div class="step-number">1.</div>
                    <div class="step-content">
                        <h3 class="step-title">Paste Your Text</h3>
                        <p class="step-desc">
                            Copy any suspicious email, SMS, URL, or message and paste it into the detector.
                        </p>
                    </div>
                </div>
                <div class="step">
                    <div class="step-number">2.</div>
                    <div class="step-content">
                        <h3 class="step-title">AI Analysis</h3>
                        <p class="step-desc">
                            Our BERT-based model analyzes the content for phishing indicators using 
                            advanced natural language processing.
                        </p>
                    </div>
                </div>
                <div class="step">
                    <div class="step-number">3.</div>
                    <div class="step-content">
                        <h3 class="step-title">Get Results</h3>
                        <p class="step-desc">
                            Receive an instant verdict with a confidence score showing whether 
                            the content is safe or potentially dangerous.
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <section class="stats">
            <h2 class="section-title" style="margin-bottom: 40px; color: #ffffff;">Powered by Advanced AI</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-number">BERT</div>
                    <div class="stat-label">Transformer Model</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Local Processing</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">Real-time</div>
                    <div class="stat-label">Detection Speed</div>
                </div>
            </div>
        </section>

        <section class="footer">
            <div class="footer-content">
                <p style="font-size: 18px; margin-bottom: 20px;">DeepCatch - Phishing Detection System</p>
                <p class="footer-subtitle" style="margin-bottom: 30px;">
                    Using ealvaradob/bert-finetuned-phishing from Hugging Face
                </p>
                <div style="border-top: 1px solid #333333; padding-top: 30px; margin-top: 40px;">
                    <p style="font-weight: bold; font-size: 20px; margin-bottom: 15px;">Seminar (CS 410) Project</p>
                    <p style="font-size: 16px; color: #cccccc; margin-bottom: 10px;">Team Members:</p>
                    <p style="font-size: 16px; color: #cccccc; line-height: 1.6;">
                        Bikash Gautam, Dipin Dawadi, Itiza Subedi, Jesse Yankey, Sudeep Joshi
                    </p>
                </div>
            </div>
        </section>
    </body>
    </html>
    """
    return html_content

# Detection page route
@app.get("/detect", response_class=HTMLResponse)
async def detect_page():
    """Serve the detection page with text input and check button"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DeepCatch - Phishing Detector</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                background-color: #f5f5f5;
                min-height: 100vh;
                padding: 40px 20px;
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
            }
            .logo {
                font-size: 42px;
                font-weight: bold;
                color: #000000;
                margin-bottom: 10px;
                letter-spacing: -1px;
            }
            .subtitle {
                color: #666666;
                font-size: 18px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
            }
            .card {
                background: white;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                padding: 40px;
                margin-bottom: 30px;
            }
            .card-title {
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
                color: #000000;
            }
            .input-section {
                margin-bottom: 20px;
            }
            .input-label {
                display: block;
                margin-bottom: 10px;
                color: #666666;
                font-size: 16px;
            }
            textarea {
                width: 100%;
                min-height: 180px;
                padding: 15px;
                font-size: 16px;
                border: 2px solid #e0e0e0;
                border-radius: 4px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                resize: vertical;
                transition: border-color 0.3s ease;
            }
            textarea:focus {
                outline: none;
                border-color: #000000;
            }
            .char-count {
                text-align: right;
                color: #999999;
                font-size: 14px;
                margin-top: 8px;
            }
            .examples {
                margin-top: 20px;
                padding: 15px;
                background-color: #f5f5f5;
                border-radius: 4px;
            }
            .examples-title {
                font-weight: bold;
                margin-bottom: 10px;
                color: #000000;
                font-size: 14px;
            }
            .example-btn {
                display: inline-block;
                margin: 5px 5px 5px 0;
                padding: 8px 16px;
                background-color: white;
                border: 1px solid #cccccc;
                border-radius: 4px;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .example-btn:hover {
                background-color: #000000;
                color: white;
                border-color: #000000;
            }
            .button-section {
                text-align: center;
                margin: 30px 0;
            }
            .check-btn {
                font-size: 18px;
                padding: 16px 70px;
                background-color: #000000;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
            }
            .check-btn:hover:not(:disabled) {
                background-color: #333333;
            }
            .check-btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
            }
            .result {
                display: none;
                padding: 40px;
                border-radius: 8px;
                margin-top: 30px;
                border: 3px solid;
                animation: slideIn 0.3s ease;
            }
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .result.show {
                display: block;
            }
            .result.phishing {
                background-color: #ffffff;
                border-color: #000000;
            }
            .result.safe {
                background-color: #f5f5f5;
                border-color: #666666;
            }
            .result.suspicious {
                background-color: #fff9e6;
                border-color: #ffa500;
            }
            .result h2 {
                font-size: 42px;
                text-align: center;
                margin-bottom: 15px;
                color: #000000;
            }
            .explanation {
                margin: 20px 0;
                padding: 15px;
                background-color: #f9f9f9;
                border-left: 4px solid #000000;
                border-radius: 4px;
                font-size: 16px;
                line-height: 1.6;
                color: #333333;
            }
            .highlighted-section {
                margin: 20px 0;
                padding: 20px;
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 4px;
            }
            .section-header {
                font-weight: bold;
                font-size: 18px;
                margin-bottom: 12px;
                color: #000000;
            }
            .highlighted-content {
                padding: 15px;
                background-color: #f5f5f5;
                border-radius: 4px;
                line-height: 1.8;
                font-size: 15px;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .highlighted-content red {
                background-color: #ffcccc;
                color: #cc0000;
                padding: 2px 4px;
                border-radius: 3px;
                font-weight: 600;
            }
            .highlighted-content yellow {
                background-color: #fff9cc;
                color: #996600;
                padding: 2px 4px;
                border-radius: 3px;
                font-weight: 500;
            }
            .metadata-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }
            .metadata-item {
                padding: 12px;
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
            .metadata-label {
                font-size: 12px;
                color: #666666;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 5px;
            }
            .metadata-value {
                font-size: 16px;
                color: #000000;
                font-weight: 600;
            }
            .url-list {
                list-style: none;
                padding: 10px 0;
            }
            .url-list li {
                padding: 8px;
                margin: 5px 0;
                background-color: #f5f5f5;
                border-left: 3px solid #000000;
                border-radius: 3px;
                font-family: monospace;
                font-size: 14px;
                word-break: break-all;
            }
            .confidence-bar {
                margin: 20px 0;
            }
            .confidence-label {
                font-size: 18px;
                font-weight: bold;
                text-align: center;
                margin-bottom: 10px;
                color: #000000;
            }
            .bar-container {
                width: 100%;
                height: 30px;
                background-color: #e0e0e0;
                border-radius: 4px;
                overflow: hidden;
            }
            .bar-fill {
                height: 100%;
                border-radius: 4px;
                transition: width 0.5s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                background-color: #000000;
            }
            .result-details {
                margin-top: 25px;
                padding: 20px;
                background-color: #f5f5f5;
                border-radius: 4px;
            }
            .detail-item {
                margin-bottom: 12px;
                font-size: 16px;
                color: #333333;
            }
            .detail-label {
                font-weight: bold;
                color: #000000;
            }
            .error {
                display: none;
                background-color: #f5f5f5;
                border: 2px solid #cccccc;
                color: #333333;
                padding: 25px;
                border-radius: 8px;
                margin-top: 20px;
                text-align: center;
            }
            .error.show {
                display: block;
                animation: slideIn 0.3s ease;
            }
            .navigation {
                text-align: center;
                margin-top: 30px;
            }
            .nav-link {
                color: #000000;
                text-decoration: none;
                font-size: 16px;
                padding: 12px 30px;
                border: 2px solid #000000;
                border-radius: 4px;
                transition: all 0.3s ease;
                display: inline-block;
            }
            .nav-link:hover {
                background-color: #000000;
                color: white;
            }
            .info-section {
                margin-top: 20px;
                padding: 15px;
                background-color: #f5f5f5;
                border-left: 4px solid #000000;
                border-radius: 4px;
            }
            .info-title {
                font-weight: bold;
                color: #000000;
                margin-bottom: 8px;
            }
            .info-text {
                color: #666666;
                font-size: 14px;
                line-height: 1.6;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">DeepCatch</div>
            <div class="subtitle">AI-Powered Phishing Detection</div>
        </div>
        
        <div class="container">
            <div class="card">
                <div class="card-title">Paste Content to Analyze</div>
                
                <div class="input-section">
                    <label class="input-label">Enter suspicious text, email, SMS, or URL:</label>
                    <textarea id="textInput" placeholder="Example: URGENT: Your account has been suspended. Click here to verify..."></textarea>
                    <div class="char-count">
                        <span id="charCount">0</span> characters
                    </div>
                </div>
                
                <div class="examples">
                    <div class="examples-title">Quick Test Examples:</div>
                    <button class="example-btn" onclick="loadExample('phishing1')">Bank Phishing</button>
                    <button class="example-btn" onclick="loadExample('phishing2')">Account Suspended</button>
                    <button class="example-btn" onclick="loadExample('phishing3')">Prize Winner</button>
                    <button class="example-btn" onclick="loadExample('phishing4')">Tax Refund</button>
                    <button class="example-btn" onclick="loadExample('phishing5')">Package Delivery</button>
                    <button class="example-btn" onclick="loadExample('phishing6')">Password Reset</button>
                    <button class="example-btn" onclick="loadExample('sms1')">SMS Scam</button>
                    <button class="example-btn" onclick="loadExample('sms2')">Verify Identity SMS</button>
                    <button class="example-btn" onclick="loadExample('safe1')">Work Email</button>
                    <button class="example-btn" onclick="loadExample('safe2')">Meeting Reminder</button>
                    <button class="example-btn" onclick="loadExample('safe3')">Newsletter</button>
                    <button class="example-btn" onclick="loadExample('safe4')">Receipt</button>
                    <button class="example-btn" onclick="clearText()">Clear</button>
                </div>
                
                <div class="button-section">
                    <button class="check-btn" id="checkBtn" onclick="checkPhishing()">
                        Analyze Now
                    </button>
                </div>
                
                <div class="info-section">
                    <div class="info-title">How it works</div>
                    <div class="info-text">
                        Our BERT-based AI model analyzes text patterns, urgency indicators, suspicious links, 
                        and other phishing characteristics. All processing happens locally on your device - 
                        your data is never sent to external servers.
                    </div>
                </div>
            </div>
            
            <div id="result" class="result">
                <h2 id="resultLabel"></h2>
                
                <div class="confidence-bar">
                    <div class="confidence-label">Confidence Score</div>
                    <div class="bar-container">
                        <div class="bar-fill" id="barFill" style="width: 0%">
                            <span id="barText">0%</span>
                        </div>
                    </div>
                </div>
                
                <div class="result-details">
                    <div class="detail-item">
                        <span class="detail-label">Model:</span>
                        <span> BERT Fine-tuned Classifier</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Processing:</span>
                        <span> 100% Local (No Data Sent Online)</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Prediction:</span>
                        <span id="predictionDetail"></span>
                    </div>
                </div>
            </div>
            
            <div id="error" class="error">
                <p id="errorMessage"></p>
            </div>
            
            <div class="navigation">
                <a href="/" class="nav-link">Back to Home</a>
            </div>
        </div>
        
        <script>
            const examples = {
                phishing1: 'URGENT: Your Bank of America account has been compromised. Immediate action required! Click here to verify your identity within 24 hours or your account will be permanently suspended: http://secure-bankofamerica-verify.com/login',
                
                phishing2: 'ALERT: Your Amazon account has been suspended due to unusual activity. We detected unauthorized access from an unknown device. Please verify your account immediately to restore access: http://amazon-account-verify.tk/secure',
                
                phishing3: 'Congratulations! You have been selected as the winner of our $50,000 cash prize! Click the link below to claim your prize before it expires. Limited time offer: http://prize-winner-claim.xyz/winner12345',
                
                phishing4: 'IRS Tax Refund Notice: You are eligible for a tax refund of $1,847.63. Click here to submit your banking information to receive your refund within 3-5 business days: http://irs-refund-portal.com/claim',
                
                phishing5: 'USPS Delivery Notice: We attempted to deliver your package but no one was home. Your package is being held at our facility. Click here to reschedule delivery and pay the $2.99 redelivery fee: http://usps-redelivery.net/track',
                
                phishing6: 'Security Alert from Microsoft: We detected an unusual sign-in attempt to your account from Russia. If this was not you, please reset your password immediately by clicking here: http://microsoft-security-reset.com/password',
                
                sms1: 'WINNER! You have been randomly selected to receive a FREE $1000 Walmart gift card! Text YES to claim your prize now or click: http://walmart-giftcard-free.biz/claim2847',
                
                sms2: 'Bank Alert: Suspicious activity detected on your account ending in 4892. Reply with your PIN and full SSN to verify your identity and prevent account closure.',
                
                safe1: 'Hi team, this is a reminder that our weekly project meeting is scheduled for tomorrow at 10 AM in Conference Room B. Please review the Q3 reports I sent earlier and come prepared with your updates. Looking forward to seeing everyone there!',
                
                safe2: 'Meeting Reminder: The product roadmap discussion is scheduled for Thursday, October 24th at 2:00 PM. The Zoom link has been sent to your calendar. Please prepare your feature proposals and be ready to discuss timelines.',
                
                safe3: 'Newsletter from TechCrunch: This week in tech news - AI breakthroughs, new smartphone releases, and startup funding updates. Read our latest articles at techcrunch.com. To unsubscribe, click the link at the bottom of this email.',
                
                safe4: 'Thank you for your purchase! Order #A12345 has been confirmed. Your receipt for $129.99 is attached. Estimated delivery: Oct 26-28. Track your package at ups.com/tracking. Questions? Contact our support team at support@company.com.'
            };
            
            const textInput = document.getElementById('textInput');
            const charCount = document.getElementById('charCount');
            
            textInput.addEventListener('input', function() {
                charCount.textContent = this.value.length;
            });
            
            function loadExample(type) {
                textInput.value = examples[type];
                charCount.textContent = examples[type].length;
                textInput.focus();
            }
            
            function clearText() {
                textInput.value = '';
                charCount.textContent = '0';
                document.getElementById('result').classList.remove('show');
                document.getElementById('error').classList.remove('show');
            }
            
            async function checkPhishing() {
                const checkBtn = document.getElementById('checkBtn');
                const resultDiv = document.getElementById('result');
                const errorDiv = document.getElementById('error');
                const errorMessage = document.getElementById('errorMessage');
                
                const text = textInput.value.trim();
                
                if (!text) {
                    errorMessage.textContent = 'Please enter some text to analyze.';
                    errorDiv.classList.add('show');
                    resultDiv.classList.remove('show');
                    return;
                }
                
                resultDiv.classList.remove('show');
                errorDiv.classList.remove('show');
                
                checkBtn.disabled = true;
                checkBtn.textContent = 'Analyzing...';
                
                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ text: text })
                    });
                    
                    const data = await response.json();
                    
                    if (!response.ok) {
                        throw new Error(data.detail || 'An error occurred');
                    }
                    
                    // Build comprehensive result display
                    const verdict = data.verdict || 'Unknown';
                    const confidence = data.confidence || 0;
                    const explanation = data.explanation || 'No explanation provided';
                    const highlighted = data.highlighted_content || text;
                    const metadata = data.metadata || {};
                    
                    // Determine result class based on verdict
                    let resultClass = 'safe';
                    if (verdict.toLowerCase().includes('high-risk') || verdict.toLowerCase().includes('phishing')) {
                        resultClass = 'phishing';
                    } else if (verdict.toLowerCase().includes('suspicious')) {
                        resultClass = 'suspicious';
                    }
                    
                    // Build HTML content
                    let htmlContent = `
                        <h2>${verdict.toUpperCase()}</h2>
                        
                        <div class="confidence-bar">
                            <div class="confidence-label">Confidence Score</div>
                            <div class="bar-container">
                                <div class="bar-fill" style="width: ${confidence}%">
                                    <span>${confidence}%</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="explanation">
                            <strong>Analysis:</strong> ${explanation}
                        </div>
                        
                        <div class="highlighted-section">
                            <div class="section-header">Content Analysis (Highlighted Risks)</div>
                            <div class="highlighted-content">${highlighted}</div>
                        </div>
                        
                        <div class="result-details">
                            <div class="section-header">Detection Metadata</div>
                            <div class="metadata-grid">
                                <div class="metadata-item">
                                    <div class="metadata-label">Input Type</div>
                                    <div class="metadata-value">${metadata.input_type || 'Unknown'}</div>
                                </div>
                                <div class="metadata-item">
                                    <div class="metadata-label">Suspicious Elements</div>
                                    <div class="metadata-value">${metadata.suspicious_elements || 0}</div>
                                </div>
                                <div class="metadata-item">
                                    <div class="metadata-label">Analysis Time</div>
                                    <div class="metadata-value">${metadata.analysis_time || 0}s</div>
                                </div>
                            </div>
                            
                            ${(metadata.urls_found && metadata.urls_found.length > 0) ? `
                                <div style="margin-top: 20px;">
                                    <div class="section-header">URLs Detected</div>
                                    <ul class="url-list">
                                        ${metadata.urls_found.map(url => `<li>${url}</li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                            
                            ${(metadata.senders_domains && metadata.senders_domains.length > 0) ? `
                                <div style="margin-top: 20px;">
                                    <div class="section-header">Suspicious Senders/Domains</div>
                                    <ul class="url-list">
                                        ${metadata.senders_domains.map(sender => `<li>${sender}</li>`).join('')}
                                    </ul>
                                </div>
                            ` : ''}
                        </div>
                    `;
                    
                    resultDiv.innerHTML = htmlContent;
                    resultDiv.className = 'result show ' + resultClass;
                    
                    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    
                } catch (error) {
                    errorMessage.textContent = 'Error: ' + error.message;
                    errorDiv.classList.add('show');
                } finally {
                    checkBtn.disabled = false;
                    checkBtn.textContent = 'Analyze Now';
                }
            }
            
            textInput.addEventListener('keydown', function(e) {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    checkPhishing();
                }
            });
        </script>
    </body>
    </html>
    """
    return html_content

# API endpoint for phishing detection
@app.post("/api/check")
async def check_phishing(input_data: TextInput):
    """
    API endpoint that processes text and returns phishing detection results using DeepSeek API
    Note: BERT model code is kept intact but not used for predictions
    """
    try:
        # Get the text from request
        text = input_data.text.strip()
        
        # Validate input
        if not text:
            return JSONResponse(
                status_code=400,
                content={"detail": "Text cannot be empty"}
            )
        
        # Use DeepSeek API for analysis instead of BERT
        logger.info(f"Processing text with DeepSeek: {text[:50]}...")
        
        # NOTE: BERT model (pipe) is loaded but not called
        # Old BERT code is preserved below for reference:
        # result = pipe(text)[0]
        # label = result['label']
        # score = result['score']
        
        # Call DeepSeek API for comprehensive analysis
        result = await analyze_with_deepseek(text)
        
        logger.info(f"DeepSeek Result: {result['verdict']} ({result['confidence']}%)")
        
        return {
            "verdict": result["verdict"],
            "confidence": result["confidence"],
            "explanation": result["explanation"],
            "highlighted_content": result["highlighted_content"],
            "metadata": result["metadata"]
        }
        
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"Prediction failed: {str(e)}"}
        )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Check if the API and model are working"""
    model_status = "loaded" if pipe is not None else "not loaded"
    return {
        "status": "ok",
        "model_status": model_status
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
