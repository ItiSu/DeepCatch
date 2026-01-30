# DeepCatch - Project Architecture

A comprehensive guide to understanding the system architecture, components, and data flow of the DeepCatch phishing detection application.

## Table of Contents

- [System Overview](#system-overview)
- [Architecture Diagram](#architecture-diagram)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Technology Stack Explained](#technology-stack-explained)
- [Code Structure](#code-structure)
- [Sequence Diagrams](#sequence-diagrams)
- [Deployment Architecture](#deployment-architecture)

## System Overview

DeepCatch is built using a **three-tier architecture** that separates concerns into distinct layers:

1. **Presentation Layer** - User interface and client-side logic
2. **Application Layer** - API server and business logic
3. **Model Layer** - Machine learning inference

This architecture ensures:
- **Separation of Concerns** - Each layer has a specific responsibility
- **Maintainability** - Changes in one layer don't affect others
- **Scalability** - Each layer can be optimized independently
- **Testability** - Components can be tested in isolation

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        USER BROWSER                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Presentation Layer (Frontend)                   │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │     HTML     │  │     CSS      │  │  JavaScript  │ │ │
│  │  │  (Structure) │  │   (Styling)  │  │   (Logic)    │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP/HTTPS
                            │ (JSON API)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  LOCAL SERVER (127.0.0.1:8000)              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Application Layer (Backend)                     │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │   Uvicorn    │  │   FastAPI    │  │   Pydantic   │ │ │
│  │  │  (ASGI       │  │  (Web        │  │  (Data       │ │ │
│  │  │   Server)    │  │   Framework) │  │   Validation)│ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │ Python Function Call
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Model Layer (ML)                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │ Transformers │  │   PyTorch    │  │  BERT Model  │ │ │
│  │  │  (Pipeline)  │  │   (Engine)   │  │  (Weights)   │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
│                            │                                  │
│                            ▼                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Local Model Cache                               │ │
│  │  ~/.cache/huggingface/hub/                             │ │
│  │  - Model weights (~1.3 GB)                             │ │
│  │  - Tokenizer files                                      │ │
│  │  - Configuration files                                  │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Presentation Layer (Frontend)

#### **HTML (Structure)**
- **Purpose:** Defines the structure and content of web pages
- **Files:** Embedded in `main.py` as strings
- **Key Elements:**
  - Homepage with hero section and information
  - Detection page with input form
  - Result display areas
  - Navigation links

#### **CSS (Styling)**
- **Purpose:** Controls visual appearance and layout
- **Approach:** Inline styles in HTML
- **Design System:**
  - Black (#000000) - Primary color
  - White (#FFFFFF) - Secondary color
  - Grey shades - Text and borders
  - Responsive grid layouts
  - Smooth animations and transitions

#### **JavaScript (Client Logic)**
- **Purpose:** Handles user interactions and API communication
- **Key Functions:**
  - `checkPhishing()` - Sends text to API
  - `loadExample()` - Loads example texts
  - `clearText()` - Resets the form
- **Features:**
  - Async/await for API calls
  - Error handling
  - DOM manipulation
  - Event listeners

### 2. Application Layer (Backend)

#### **Uvicorn (ASGI Server)**
```python
# How it works:
uvicorn main:app --reload

# Breakdown:
- uvicorn: The ASGI server executable
- main: The Python module name (main.py)
- app: The FastAPI application instance
- --reload: Watch for code changes and restart
```

**Responsibilities:**
- Listens on port 8000
- Handles HTTP requests/responses
- Manages connections
- Routes traffic to FastAPI

#### **FastAPI (Web Framework)**
```python
app = FastAPI(title="DeepCatch - Phishing Detection")

@app.get("/")  # Route decorator
async def homepage():  # Async handler
    return HTMLResponse(html_content)
```

**Responsibilities:**
- URL routing
- Request/response handling
- Automatic validation
- API documentation
- Dependency injection

**Key Endpoints:**
1. `GET /` - Serves homepage
2. `GET /detect` - Serves detection page  
3. `POST /api/check` - Processes phishing detection
4. `GET /health` - Health check endpoint

#### **Pydantic (Data Validation)**
```python
class TextInput(BaseModel):
    text: str
```

**Responsibilities:**
- Input validation
- Type checking
- Automatic documentation
- Data serialization

### 3. Model Layer (Machine Learning)

#### **Transformers Pipeline**
```python
pipe = pipeline(
    "text-classification",
    model="ealvaradob/bert-finetuned-phishing"
)
```

**Purpose:** Simplifies model loading and inference

**What it does:**
1. Downloads model if not cached
2. Loads tokenizer
3. Loads model weights
4. Provides simple interface: `pipe(text)`

#### **PyTorch (Deep Learning Engine)**
**Responsibilities:**
- Tensor operations
- GPU acceleration (if available)
- Model inference
- Gradient computation (not used in inference)

#### **BERT Model Architecture**
```
Input Text: "URGENT: Click here now!"
     │
     ▼
┌─────────────────────┐
│   Tokenization      │  → ["[CLS]", "URGENT", ":", "Click", "here", "now", "!", "[SEP]"]
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  Token to IDs       │  → [101, 12287, 18833, 102, ...]
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  Embeddings         │  → 768-dimensional vectors
│  - Token embeddings │
│  - Position embeddings │
│  - Segment embeddings  │
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  12 Transformer     │
│  Layers             │  → Each layer has:
│  (Self-Attention)   │     - Multi-head attention
│                     │     - Feed-forward network
│                     │     - Layer normalization
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  Classification     │  → [Phishing: 0.95, Safe: 0.05]
│  Head               │
└─────────────────────┘
     │
     ▼
    Output: "PHISHING" with 95% confidence
```

## Data Flow

### Complete Request-Response Cycle

```
1. USER ACTION
   User pastes text and clicks "Analyze Now"
   
2. JAVASCRIPT
   ┌──────────────────────────────────────┐
   │ function checkPhishing() {           │
   │   fetch('/api/check', {              │
   │     method: 'POST',                  │
   │     body: JSON.stringify({text: txt})│
   │   })                                 │
   │ }                                    │
   └──────────────────────────────────────┘
          │
          │ HTTP POST Request
          │ Content-Type: application/json
          │ Body: {"text": "..."}
          ▼
3. UVICORN
   Receives HTTP request on port 8000
   Parses headers and body
   Routes to FastAPI
          │
          ▼
4. FASTAPI
   ┌──────────────────────────────────────┐
   │ @app.post("/api/check")              │
   │ async def check_phishing(            │
   │     input_data: TextInput            │
   │ ):                                   │
   │   # Validation happens here          │
   └──────────────────────────────────────┘
          │
          │ Pydantic validates:
          │ - Field exists
          │ - Correct type
          │ - Not empty
          ▼
5. PYDANTIC VALIDATION
   ┌──────────────────────────────────────┐
   │ class TextInput(BaseModel):          │
   │     text: str                        │
   │                                      │
   │ ✓ Valid: Continue                   │
   │ ✗ Invalid: Return 422 error         │
   └──────────────────────────────────────┘
          │
          │ Validated data
          ▼
6. MODEL INFERENCE
   ┌──────────────────────────────────────┐
   │ text = input_data.text.strip()       │
   │ result = pipe(text)[0]               │
   │                                      │
   │ Internally:                          │
   │  - Tokenize text                    │
   │  - Convert to tensors               │
   │  - Run through BERT                 │
   │  - Get classification               │
   └──────────────────────────────────────┘
          │
          │ {"label": "LABEL_1", "score": 0.95}
          ▼
7. RESPONSE FORMATTING
   ┌──────────────────────────────────────┐
   │ if label in ['phishing', 'label_1']: │
   │     prediction = "PHISHING"          │
   │ else:                                │
   │     prediction = "SAFE"              │
   │                                      │
   │ confidence = round(score * 100, 1)   │
   │                                      │
   │ return {                             │
   │   "prediction": prediction,          │
   │   "confidence": confidence           │
   │ }                                    │
   └──────────────────────────────────────┘
          │
          │ JSON Response
          ▼
8. FASTAPI → UVICORN
   Serializes response to JSON
   Adds HTTP headers
   Sends response
          │
          │ HTTP 200 OK
          │ Content-Type: application/json
          │ Body: {"prediction": "PHISHING", "confidence": 95.0}
          ▼
9. JAVASCRIPT
   ┌──────────────────────────────────────┐
   │ const data = await response.json();  │
   │                                      │
   │ resultLabel.textContent =            │
   │     data.prediction;                 │
   │                                      │
   │ barFill.style.width =                │
   │     data.confidence + '%';           │
   └──────────────────────────────────────┘
          │
          ▼
10. USER SEES RESULT
    Display shows: "PHISHING" with 95.0% confidence
```

## Technology Stack Explained

### Why These Technologies?

#### **Python**
- **Chosen because:**
  - Excellent ML/AI library support
  - Simple syntax for rapid development
  - Strong community and documentation
  
- **Alternatives considered:**
  - JavaScript/Node.js (less mature ML libraries)
  - Java (more verbose, slower development)

#### **FastAPI**
- **Chosen because:**
  - Modern async support
  - Automatic API documentation
  - Built-in validation
  - Fast performance
  
- **Alternatives considered:**
  - Flask (older, synchronous)
  - Django (too heavy for this use case)

#### **Hugging Face Transformers**
- **Chosen because:**
  - Easy access to pre-trained models
  - Consistent API
  - Automatic model downloading
  - Well-documented
  
- **Alternatives considered:**
  - TensorFlow (more complex API)
  - Custom model training (too time-consuming)

#### **PyTorch**
- **Chosen because:**
  - Required by Transformers library
  - Industry standard for research
  - Dynamic computation graphs
  
- **Alternatives considered:**
  - TensorFlow (Transformers uses PyTorch by default)

## Code Structure

### main.py Organization

```python
# 1. IMPORTS
from fastapi import FastAPI, Request
from transformers import pipeline
# ... other imports

# 2. CONFIGURATION
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 3. APPLICATION INITIALIZATION
app = FastAPI(title="DeepCatch")

# 4. MODEL LOADING
pipe = pipeline("text-classification", model="...")

# 5. DATA MODELS
class TextInput(BaseModel):
    text: str

# 6. ROUTE HANDLERS
@app.get("/")
async def homepage():
    # Returns HTML

@app.post("/api/check")
async def check_phishing(input_data: TextInput):
    # ML inference logic

# 7. SERVER STARTUP
if __name__ == "__main__":
    uvicorn.run(app)
```

### Key Design Patterns

#### **Dependency Injection**
```python
async def check_phishing(input_data: TextInput):
    # FastAPI automatically:
    # 1. Parses request body
    # 2. Validates against TextInput model
    # 3. Injects validated data
```

#### **Pipeline Pattern**
```python
# Transformers pipeline encapsulates:
text → tokenize → embed → transform → classify
```

#### **Async/Await**
```python
async def homepage():
    # Non-blocking, allows concurrent requests
```

## Sequence Diagrams

### Successful Detection Flow

```
User          Browser         FastAPI        Model         Response
 │               │               │             │              │
 │  Type text    │               │             │              │
 │──────────────>│               │             │              │
 │               │               │             │              │
 │  Click button │               │             │              │
 │──────────────>│               │             │              │
 │               │               │             │              │
 │               │ POST /api/check             │              │
 │               │──────────────>│             │              │
 │               │               │             │              │
 │               │               │ Validate    │              │
 │               │               │────────┐    │              │
 │               │               │        │    │              │
 │               │               │<───────┘    │              │
 │               │               │             │              │
 │               │               │ pipe(text)  │              │
 │               │               │────────────>│              │
 │               │               │             │              │
 │               │               │             │ Tokenize     │
 │               │               │             │─────────┐    │
 │               │               │             │         │    │
 │               │               │             │<────────┘    │
 │               │               │             │              │
 │               │               │             │ BERT Forward │
 │               │               │             │─────────┐    │
 │               │               │             │         │    │
 │               │               │             │<────────┘    │
 │               │               │             │              │
 │               │               │ {"label": "LABEL_1",       │
 │               │               │  "score": 0.95}            │
 │               │               │<────────────│              │
 │               │               │             │              │
 │               │               │ Format      │              │
 │               │               │────────┐    │              │
 │               │               │        │    │              │
 │               │               │<───────┘    │              │
 │               │               │             │              │
 │               │ JSON Response │             │              │
 │               │<──────────────│             │              │
 │               │               │             │              │
 │               │ Update UI     │             │              │
 │               │────────┐      │             │              │
 │               │        │      │             │              │
 │               │<───────┘      │             │              │
 │               │               │             │              │
 │  See result   │               │             │              │
 │<──────────────│               │             │              │
```

### Error Handling Flow

```
Browser         FastAPI        Validation
   │               │               │
   │ POST (bad data)               │
   │──────────────>│               │
   │               │               │
   │               │ Validate      │
   │               │──────────────>│
   │               │               │
   │               │               │ ✗ Invalid
   │               │               │─────────┐
   │               │               │         │
   │               │ 422 Error    │<────────┘
   │               │<──────────────│
   │               │               │
   │ Error display │               │
   │<──────────────│               │
```

## Deployment Architecture

### Development Setup
```
Developer Machine
├── Code Editor (VSCode)
├── Python 3.8+
├── Local Server (127.0.0.1:8000)
└── Browser (Chrome/Firefox)
```

### Local Execution
```
Process Flow:
1. Terminal: uvicorn main:app --reload
2. Uvicorn starts on port 8000
3. FastAPI app initializes
4. Model loads (or loads from cache)
5. Server ready for requests
6. Browser connects to localhost:8000
```

### Resource Requirements

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| Python Runtime | 10-20% | 200 MB | - |
| Model Cache | - | - | 1.5 GB |
| Model Inference | 50-80% | 2-3 GB | - |
| **Total** | **~60-100%** | **~2.5-3.5 GB** | **~1.5 GB** |

## Security Considerations

### Data Privacy
- **No external API calls** during inference
- **No data logging** or storage
- **Local processing** only
- **No cookies** or tracking

### Input Validation
```python
# Pydantic validates:
- Type correctness
- Required fields
- String format
```

### Error Handling
```python
try:
    result = pipe(text)
except Exception as e:
    logger.error(f"Error: {e}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Prediction failed"}
    )
```

## Performance Optimization

### Model Caching
- Model loaded once at startup
- Reused for all requests
- Saves ~5-10 seconds per request

### Async Operations
- Non-blocking request handling
- Multiple concurrent requests supported
- Better resource utilization

### Response Optimization
- Minimal JSON payloads
- Client-side rendering
- No unnecessary data transfer

## Monitoring and Debugging

### Logging
```python
logger.info(f"Processing text: {text[:50]}...")
logger.info(f"Result: {prediction} ({confidence}%)")
```

### Health Check
```bash
curl http://127.0.0.1:8000/health
```

Response:
```json
{
  "status": "ok",
  "model_status": "loaded"
}
```

## Future Architecture Improvements

1. **Add Database Layer**
   - Store analysis history
   - User accounts
   - Statistics tracking

2. **Implement Caching**
   - Redis for frequently analyzed texts
   - Reduce redundant model calls

3. **Add Queue System**
   - Celery for background processing
   - Handle high traffic loads

4. **Microservices**
   - Separate model service
   - Independent scaling
   - Better fault isolation

5. **API Gateway**
   - Rate limiting
   - Authentication
   - Request routing

---

This architecture document provides a comprehensive understanding of how DeepCatch is built and how its components work together to provide accurate phishing detection.
