from pydantic import BaseModel, EmailStr, HttpUrl, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ReportStatus(str, Enum):
    GREEN = "green"
    ORANGE = "orange"
    RED = "red"

class URLReportBase(BaseModel):
    url: str
    reporting_time: datetime
    reporter_name: Optional[str] = None
    reporter_email: Optional[EmailStr] = None
    image_data: Optional[str] = None  # Base64 encoded image

    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class URLReportCreate(URLReportBase):
    pass

class URLReport(URLReportBase):
    id: int
    frequency: int = 1
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SecurityCheckRequest(BaseModel):
    url: str

    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class SecurityCheckResponse(BaseModel):
    url: str
    ai_prediction: bool
    ai_confidence: Optional[float]
    api_verification: Dict[str, bool]
    final_status: ReportStatus
    is_malicious: bool

class EncryptedRequest(BaseModel):
    encrypted_data: str

class EncryptedResponse(BaseModel):
    encrypted_data: str