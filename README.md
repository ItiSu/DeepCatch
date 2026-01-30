# DeepCatch - AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-FFD21E?style=flat&logo=huggingface&logoColor=black)](https://huggingface.co/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<img width="2557" height="534" alt="Image" src="https://github.com/user-attachments/assets/5b468352-b89a-4dae-9b43-007fe4d1a077" />

<img width="2560" height="1093" alt="Image" src="https://github.com/user-attachments/assets/a1d64493-b9b7-465a-8c05-ca66604077c6" />

<img width="2559" height="975" alt="Image" src="https://github.com/user-attachments/assets/fb3e231c-f142-46ae-849d-20755738e570" />

A sophisticated phishing detection web application that combines a fine-tuned BERT model with advanced AI explanations. DeepCatch uses the `ealvaradob/bert-finetuned-phishing` model from Hugging Face for accurate classification, and DeepSeek AI to generate detailed explanations of why content is flagged as phishing.

##  Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Model Details](#model-details)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)


## Overview

DeepCatch is a web-based phishing detection system. It combines two AI technologies:

1. **Hugging Face BERT Model** - For initial phishing classification (Phishing vs. Safe)
2. **DeepSeek AI** - For generating detailed explanations of phishing indicators

This hybrid approach provides both accurate detection and comprehensive analysis to help users understand why content is flagged as suspicious.

## Features

### 🔍 Dual AI-Powered Detection
- **BERT Classification** - Uses `ealvaradob/bert-finetuned-phishing` for accurate phishing/safe classification
- **DeepSeek Explanations** - Generates natural language explanations of why content is flagged
- **Confidence Scoring** - Percentage-based confidence meter with visual bar
- **Risk Highlighting** - Highlights risky parts of content with color-coded tags

###  Rich User Interface
- Clean, modern black & white design
- Real-time text analysis
- 12 pre-loaded test examples (6 phishing + 4 safe + 2 SMS)
- Responsive design for mobile and desktop
- Character counter with visual feedback

###  Comprehensive Results
- **Classification** - Phishing or Safe verdict
- **Confidence Score** - Percentage-based confidence meter
- **AI Explanation** - Detailed explanation of why content is suspicious
- **Highlighted Content** - Risky parts marked with `<red>` and `<yellow>` tags
- **Metadata Analysis**:
  - Input type detection (Email, SMS, URL, Text)
  - Suspicious element count
  - Extracted URLs list
  - Analysis time tracking

###  Easy to Use
- Paste any text, email, SMS, or URL
- One-click analysis
- Pre-loaded test examples
- Keyboard shortcuts (Ctrl+Enter to analyze)

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Backend** | Python 3.8+ | Primary programming language |
| **Web Framework** | FastAPI | Web server and API endpoints |
| **ML Classification** | Hugging Face Transformers | BERT model for phishing detection |
| **Deep Learning** | PyTorch | Backend for running BERT |
| **AI Explanations** | DeepSeek API | Generate detailed analysis explanations |
| **ASGI Server** | Uvicorn | Run FastAPI application |
| **Data Validation** | Pydantic | API request/response validation |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript | User interface |
| **Environment** | python-dotenv | Environment variable management |

## How It Works

### 1. Input Processing
```
User pastes content → Frontend captures text → Sends to API
```

### 2. BERT Classification
The content is first analyzed by the BERT model:
- **Model**: `ealvaradob/bert-finetuned-phishing`
- **Input**: Raw text (email, SMS, URL, etc.)
- **Output**: Binary classification (Phishing/Safe) with confidence score
- **Processing**: 100% local - no data sent to external servers

### 3. DeepSeek Explanation Generation
For comprehensive analysis, DeepSeek AI generates:
- **VERDICT**: Safe / Suspicious / High-risk classification
- **CONFIDENCE**: 0-100% confidence score
- **EXPLANATION**: 2-3 sentence explanation of phishing indicators
- **HIGHLIGHTED_CONTENT**: Original text with `<red>` (high-risk) and `<yellow>` (suspicious) tags
- **METADATA**: Input type, URLs found, suspicious elements, etc.

### 4. Result Display
- BERT classification result prominently displayed
- DeepSeek explanation provides context
- Confidence visualized as a progress bar
- Content shown with color-coded risk highlighting
- Metadata presented in organized grid layout

### Complete Data Flow
```
┌─────────────┐    HTTP POST     ┌─────────────┐    
│   Browser   │ ────────────────> │   FastAPI   │ 
│  (Frontend) │                   │  (Backend)  │ 
└─────────────┘                   └──────┬──────┘ 
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
                    ▼                    ▼                    ▼
            ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
            │  BERT Model │      │ DeepSeek AI │      │  URL/Type   │
            │  (Hugging   │      │  (API Call) │      │  Detection  │
            │   Face)     │      │             │      │  (Local)    │
            └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
                   │                    │                    │
                   │ Classification     │ Explanation        │ Metadata
                   │ (Local)            │ (API)              │ (Local)
                   │                    │                    │
                   └────────────────────┼────────────────────┘
                                        │
                                        ▼
                              ┌─────────────────┐
                              │  Combine Results │
                              │  (FastAPI)       │
                              └────────┬────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │  JSON Response   │
                              │  to Browser      │
                              └─────────────────┘
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- 2-3 GB free disk space (for BERT model download)
- 4 GB RAM minimum (recommended: 8 GB)
- DeepSeek API key ([Get one here](https://platform.deepseek.com/)) - for explanations

### Step 1: Clone the Repository
```bash
git clone https://github.com/ItiSu/LogLine.git
cd LogLine
```

### Step 2: Create Virtual Environment (Recommended)
```bash
python -m venv venv

# On macOS/Linux
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the project root:
```bash
DEEPSEEK_API_KEY=your_api_key_here
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DEEPSEEK_API_KEY` | Your DeepSeek API key (for explanations) | Yes |

### Getting a DeepSeek API Key

1. Visit [DeepSeek Platform](https://platform.deepseek.com/)
2. Sign up for an account
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key to your `.env` file

**Note:** The BERT model runs completely locally and does not require an API key. Only the explanation generation feature uses DeepSeek API.

## Usage

### Start the Server
```bash
uvicorn main:app --reload
```

**What this command does:**
- `uvicorn` - Starts the ASGI server
- `main:app` - Loads the `app` object from `main.py`
- `--reload` - Enables auto-reload on code changes (development mode)

### Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:8000/
```

### Using the Detector

1. **Navigate to the Detection Page**
   - Click "Start Detection" on the homepage
   - Or go directly to `/detect`

2. **Enter Content**
   - Paste suspicious email, SMS, URL, or text
   - Or click example buttons to load test cases:
     - **Phishing Examples**: Bank phishing, Account suspended, Prize winner, Tax refund, Package delivery, Password reset
     - **SMS Examples**: SMS scam, Verify identity
     - **Safe Examples**: Work email, Meeting reminder, Newsletter, Receipt

3. **Analyze**
   - Click "Analyze Now" button
   - Or press `Ctrl+Enter` (Windows/Linux) / `Cmd+Enter` (Mac)

4. **Review Results**
   - Check the BERT classification (Phishing/Safe)
   - Review confidence score
   - Read the DeepSeek AI explanation
   - Examine highlighted risky elements
   - Review metadata (URLs, suspicious elements, etc.)

### Example Test Cases

**Phishing Example:**
```
URGENT: Your Bank of America account has been compromised. 
Immediate action required! Click here to verify your identity 
within 24 hours or your account will be permanently suspended: 
http://secure-bankofamerica-verify.com/login
```

**Safe Example:**
```
Hi team, this is a reminder that our weekly project meeting 
is scheduled for tomorrow at 10 AM in Conference Room B. 
Please review the Q3 reports I sent earlier and come prepared 
with your updates. Looking forward to seeing everyone there!
```

## API Documentation

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Homepage with project overview |
| `/detect` | GET | Phishing detection interface |
| `/api/check` | POST | Analyze text for phishing |
| `/health` | GET | Health check endpoint |

### POST /api/check

**Request:**
```json
POST /api/check
Content-Type: application/json

{
  "text": "URGENT: Click here now! http://suspicious-site.com"
}
```

**Response:**
```json
{
  "verdict": "High-risk",
  "confidence": 95,
  "explanation": "This message contains multiple phishing indicators including urgency tactics ('URGENT'), a suspicious URL with a misleading domain, and a call-to-action designed to make users click without thinking.",
  "highlighted_content": "<red>URGENT:</red> Click here now! <red>http://suspicious-site.com</red>",
  "metadata": {
    "input_type": "Text/Message",
    "suspicious_elements": 3,
    "urls_found": ["http://suspicious-site.com"],
    "senders_domains": [],
    "analysis_time": 2.34
  }
}
```

### GET /health

**Response:**
```json
{
  "status": "ok",
  "model_status": "loaded"
}
```

## Model Details

### BERT Classification Model

**Model Name:** `ealvaradob/bert-finetuned-phishing`

**Architecture:** BERT (Bidirectional Encoder Representations from Transformers)
- 12 transformer layers
- 110M parameters
- Fine-tuned for binary classification (Phishing vs. Safe)

**How BERT Works:**

1. **Tokenization**
   - Input text is split into tokens (words/subwords)
   - Special tokens [CLS] and [SEP] are added
   - Tokens are converted to numerical IDs

2. **Embedding**
   - Token IDs are converted to dense vector representations
   - Position encodings capture word order
   - Segment embeddings distinguish text segments

3. **Transformer Processing**
   - 12 layers of self-attention mechanisms
   - Each layer learns different patterns
   - Contextual understanding from both directions

4. **Classification**
   - Final layer produces probability scores
   - Binary output: Phishing or Safe
   - Confidence score (0-100%)

**Training Data:**
The model was fine-tuned on phishing and legitimate messages, learning to identify:
- Suspicious URLs and domains
- Urgency tactics (e.g., "URGENT", "Verify now")
- Impersonation attempts
- Grammar and spelling patterns
- Social engineering techniques

### DeepSeek Explanation Model

**Model:** `deepseek-chat`

**Purpose:** Generate human-readable explanations of phishing indicators

**Capabilities:**
- Analyze content for phishing patterns
- Provide detailed explanations (2-3 sentences)
- Highlight risky elements with color-coded tags
- Extract metadata (URLs, input type, suspicious elements)
- Return structured data for frontend display

## Project Structure

```
LogLine/
├── main.py                  # Main FastAPI application
├── requirements.txt         # Python dependencies
├── .env                     # Environment variables (not in git)
├── .gitignore              # Git ignore rules
├── README.md               # Project documentation
├── ARCHITECTURE.md         # Detailed architecture docs
└── LICENSE                 # License file
```

### File Descriptions

| File | Purpose |
|------|---------|
| `main.py` | Contains FastAPI routes, BERT model integration, DeepSeek API integration, HTML templates, and JavaScript |
| `requirements.txt` | Lists all Python package dependencies with versions |
| `.env` | Stores sensitive configuration (DeepSeek API key) - **never commit this** |
| `.gitignore` | Specifies files that should not be tracked by git |
| `ARCHITECTURE.md` | Detailed technical documentation about system design |

## Troubleshooting

### Model Download Issues
**Problem:** BERT model fails to download on first run
**Solution:**
- Check internet connection (needed for first download only)
- Ensure sufficient disk space (1.5 GB free)
- Check firewall settings
- Download location: `~/.cache/huggingface/hub/` (macOS/Linux) or `C:\Users\<username>\.cache\huggingface\hub\` (Windows)

### DeepSeek API Key Issues
**Problem:** "DeepSeek API client not initialized"
**Solution:**
- Check that `.env` file exists with `DEEPSEEK_API_KEY`
- Verify the API key is valid and not expired
- Ensure `python-dotenv` is installed: `pip install python-dotenv`

### Port Already in Use
**Problem:** `Address already in use`
**Solution:**
```bash
# Use a different port
uvicorn main:app --reload --port 8001
```

### Memory Issues
**Problem:** Out of memory errors
**Solution:**
- Close other applications
- Ensure at least 4 GB RAM available
- The BERT model requires ~2-3 GB RAM when loaded

### Module Import Errors
**Problem:** `ModuleNotFoundError`
**Solution:**
```bash
# Reinstall all dependencies
pip install --force-reinstall -r requirements.txt
```

### API Rate Limits
**Problem:** Analysis fails with DeepSeek rate limit error
**Solution:**
- Wait a moment before trying again
- Check your DeepSeek API usage limits
- Consider upgrading your DeepSeek plan if needed

## Performance

### Response Times
- BERT model loading: ~5-10 seconds (first run only)
- BERT classification: ~0.5-2 seconds
- DeepSeek explanation: ~2-5 seconds
- Page load: < 100ms

### Resource Usage
- Memory: ~2-3 GB (with BERT model loaded)
- CPU: Moderate during inference
- Disk: ~1.5 GB (BERT model cache)
- Network: Required for initial model download and DeepSeek API calls

## Limitations

- BERT model is limited to English text
- Very long texts (>512 tokens) may be truncated
- Requires internet connection for DeepSeek explanations
- DeepSeek API usage may incur costs
- Performance depends on hardware specifications

## Future Improvements

- [ ] Add local explanation generation (reduce API dependency)
- [ ] Implement caching for repeated analyses
- [ ] Add batch processing for multiple texts
- [ ] Create browser extension version
- [ ] Add user accounts and history tracking
- [ ] Implement email header parsing
- [ ] Add URL reputation checking
- [ ] Multi-language support
- [ ] Export analysis reports (PDF/CSV)

## Contributing

This is a class project for CS 410 Seminar. Contributions, suggestions, and feedback are welcome from team members.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Hugging Face](https://huggingface.co/) for the Transformers library and BERT models
- [ealvaradob](https://huggingface.co/ealvaradob) for the fine-tuned phishing detection model
- [DeepSeek AI](https://deepseek.com/) for the explanation generation API
- [FastAPI](https://fastapi.tiangolo.com/) team for the excellent web framework
- [PyTorch](https://pytorch.org/) team for the deep learning framework

## Support

For issues, questions, or suggestions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [ARCHITECTURE.md](ARCHITECTURE.md) file

---
