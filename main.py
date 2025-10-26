from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict
from pathlib import Path
import base64
import sys
import requests
from datetime import datetime
from urllib import parse
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os



from models import *
from database import db
from security import security_manager

app = FastAPI(
    title="Malicious URL Checker API",
    description="API for detecting malicious URLs using AI and multiple security services",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add project root to Python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import from model
try:
    from model.predict import predict_single
except ImportError as e:
    print(f"Import error: {e}")
    raise

# Mock AI model prediction function (replace with your actual implementation)
def predict_single(url: str):
    """
    AI model prediction - simple flipped logic
    Returns: (label, confidence_score)
    """
    import random
    
    # Your original logic (but flipped)
    suspicious_keywords = ['phish', 'login', 'verify', 'secure', 'account', 'banking']
    url_lower = url.lower()
    
    # FLIPPED: Now if keywords are present, it's more likely BENIGN (common legit sites)
    # If no keywords, it might be suspicious
    if any(keyword in url_lower for keyword in suspicious_keywords):
        return "benign", random.uniform(0.7, 0.95)  # Flipped to benign
    else:
        return "malicious", random.uniform(0.6, 0.9)  # Flipped to malicious

# Security API Checkers
class SecurityAPIChecker:
    def __init__(self):
        self.apis = {
            "urlscan": self.check_urlscan,
            "virustotal": self.check_virustotal,
            "phishtank": self.check_phishtank,
        }
    
    
    async def check_urlscan(self, url: str) -> bool:
        """Check URL against urlscan.io API for malicious indicators"""
        try:
            domain = parse.urlparse(url).netloc
            
            # Search for scans of this domain
            response = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                
                # If no results found, domain hasn't been scanned or is clean
                if not results:
                    return False
                
                # Check the most recent scan for malicious indicators
                latest_scan = results[0]
                scan_id = latest_scan.get('_id')
                
                # Get detailed results for the latest scan
                detail_response = requests.get(
                    f"https://urlscan.io/api/v1/result/{scan_id}/",
                    timeout=10
                )
                
                if detail_response.status_code == 200:
                    detail_data = detail_response.json()
                    
                    # Check verdict from urlscan
                    verdict = detail_data.get('verdicts', {})
                    overall = verdict.get('overall', {})
                    
                    # Return True if malicious, False if clean/unknown
                    return overall.get('malicious', False)
                
            return False
            
        except Exception as e:
            print(f"URLScan error: {e}")
            return False
    

    async def check_virustotal(self, url: str) -> bool:
        """Simplified VirusTotal check using domain search"""
        try:
            api_key = os.getenv('VIRUSTOTAL_API_KEY')
            if not api_key:
                return False
            
            # Extract domain from URL
            domain = parse.urlparse(url).netloc
            
            # Search by domain instead of URL hash (simpler approach)
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={'x-apikey': api_key},
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                print(f"VirusTotal domain check: {malicious_count} malicious engines")
                return malicious_count > 0
            else:
                print(f"VirusTotal domain check failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"VirusTotal domain error: {e}")
            return False
    
    async def check_phishtank(self, url: str) -> bool:
        """Check URL against PhishTank API"""
        try:
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url': url,
                    'format': 'json'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', {})
                return results.get('in_database', False)
                
            return False
            
        except Exception as e:
            print(f"PhishTank error: {e}")
            return False
        
    
    async def check_all_apis(self, url: str) -> Dict[str, bool]:
        """Check URL against all security APIs concurrently"""
        tasks = {
            name: checker(url) 
            for name, checker in self.apis.items()
        }
        
        # Run all API checks concurrently
        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as e:
                print(f"API check failed for {name}: {e}")
                results[name] = False
        
        return results

security_checker = SecurityAPIChecker()

# Startup event
@app.on_event("startup")
async def startup_event():
    await db.connect()
    print("Application started successfully!")

# Your existing AI endpoint (kept for compatibility)
# @app.get("/check-url")
# async def check_url(url: str):
#     """
#     Accepts a URL via query string and returns prediction
#     """
#     try:
#         # Validate URL format
#         parsed = parse.urlparse(url)
#         if not parsed.scheme or not parsed.netloc:
#             raise HTTPException(status_code=400, detail="Invalid URL format")

#         # Get prediction
#         label, probability = predict_single(url)
        
#         return {
#             "url": url,
#             "is_malicious": label == "malicious",
#             "label": label,
#             "confidence": float(probability) if probability is not None else None
#         }
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


# Enhanced security check endpoint
@app.get("/check-url-security", response_model=SecurityCheckResponse)
async def check_url_security(url: str):
    """Enhanced URL security check with multiple API verification"""
    try:
        # Validate URL
        parsed = parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL format")

        # AI model prediction
        label, probability = predict_single(url)
        ai_malicious = label == "malicious"
        
        # Check security APIs
        api_results = await security_checker.check_all_apis(url)
        
        # Determine final status - FIXED LOGIC
        # Check specifically for the three key services
        critical_services = ["urlscan", "virustotal", "phishtank"]
        any_critical_malicious = any(
            api_results.get(service, False) 
            for service in critical_services
        )
        
        # Apply the intended logic:
        # - If any critical service says malicious → RED
        # - If only AI says malicious → ORANGE  
        # - If all say false → GREEN
        if any_critical_malicious:
            final_status = ReportStatus.RED
        elif ai_malicious and not any_critical_malicious:
            final_status = ReportStatus.ORANGE
        else:
            final_status = ReportStatus.GREEN
        
        return SecurityCheckResponse(
            url=url,
            ai_prediction=ai_malicious,
            ai_confidence=float(probability) if probability is not None else None,
            api_verification=api_results,
            final_status=final_status,
            is_malicious=final_status in [ReportStatus.RED, ReportStatus.ORANGE]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Security check error: {str(e)}")
    
class EncryptedRequest(BaseModel):
    encrypted_data: str

# Use the same key as frontend (32 characters)


ENCRYPTION_KEY = '12345678901234567890123456789012'

def decrypt_data(encrypted_data: str) -> dict:
    try:
        print("Starting decryption...")
        
        # Decode base64 (CryptoJS format includes metadata)
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # For CryptoJS format, we need to extract the actual ciphertext
        # CryptoJS format: Salted__<salt><ciphertext>
        if encrypted_bytes.startswith(b'Salted__'):
            salt = encrypted_bytes[8:16]
            ciphertext = encrypted_bytes[16:]
            
            # Use OpenSSL-compatible key derivation
            derived_key = bytes()
            while len(derived_key) < 32:
                hash_data = (derived_key + ENCRYPTION_KEY.encode('utf-8') + salt) if derived_key else (ENCRYPTION_KEY.encode('utf-8') + salt)
                derived_key += hashlib.md5(hash_data).digest()
            derived_key = derived_key[:32]
        else:
            # Raw key mode
            derived_key = ENCRYPTION_KEY.encode('utf-8')
            ciphertext = encrypted_bytes
        
        cipher = AES.new(derived_key, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(ciphertext)
        decrypted_bytes = unpad(decrypted_bytes, 16, style='pkcs7')
        
        decrypted_text = decrypted_bytes.decode('utf-8')
        print(f"Decrypted successfully: {decrypted_text}")
        
        return json.loads(decrypted_text)
        
    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")
        
# Report URL endpoint
@app.post("/report-url")
async def report_url(encrypted_request: EncryptedRequest):
    """Report a URL with encrypted data"""
    try:
        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_request.encrypted_data)
        
        # Validate required fields
        required_fields = ['url', 'reporting_time', 'reporter_name', 'reporter_email']
        for field in required_fields:
            if field not in decrypted_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

        # Validate URL
        url_str = str(decrypted_data['url']).strip()
        parsed = parse.urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL format")

        # Convert reporting_time from string to datetime
        try:
            # Try ISO format first (most common)
            if isinstance(decrypted_data['reporting_time'], str):
                reporting_time = datetime.fromisoformat(decrypted_data['reporting_time'].replace('Z', '+00:00'))
            else:
                reporting_time = decrypted_data['reporting_time']
        except (ValueError, AttributeError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid date format for reporting_time: {str(e)}")

        # Validate email format
        email = str(decrypted_data['reporter_email']).strip()
        if '@' not in email or '.' not in email:
            raise HTTPException(status_code=400, detail="Invalid email format")

        # Process the decrypted data
        report_id, frequency = await db.insert_or_update_report(
            url=url_str,
            reporting_time=reporting_time,  # Now a datetime object
            reporter_name=str(decrypted_data['reporter_name']).strip(),
            reporter_email=email,
            image_data=decrypted_data.get('image_data', '')
        )

        return {
            "message": "URL reported successfully",
            "report_id": report_id,
            "frequency": frequency
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report submission error: {str(e)}")

# Get all reports endpoint
@app.get("/reports", response_model=List[URLReport])
async def get_all_reports():
    """Retrieve all reported URLs"""
    try:
        rows = await db.get_all_reports()
        reports = []
        
        for row in rows:
            reports.append(URLReport(
                id=row['id'],
                url=row['url'],
                reporting_time=row['reporting_time'],
                reporter_name=row['reporter_name'],
                reporter_email=row['reporter_email'],
                image_data=row['image_data'],
                frequency=row['frequency'],
                created_at=row['created_at'],
                updated_at=row['updated_at']
            ))
        
        return reports
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving reports: {str(e)}")


# Health check endpoint
@app.get("/")
async def root():
    return {"message": "Malicious URL Checker API is running!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)