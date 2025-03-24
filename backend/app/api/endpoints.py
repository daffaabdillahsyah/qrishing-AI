from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional, Dict
from ..models.database import get_db, URLScan
from ..services.url_scanner import URLScanner
from ..services.qr_scanner import QRScanner
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()
url_scanner = URLScanner()
qr_scanner = QRScanner()

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    is_malicious: bool
    risk_score: int
    scan_result: str
    scan_date: datetime

class QRScanResponse(BaseModel):
    success: bool
    message: str
    url: Optional[str] = None
    scan_result: Optional[Dict] = None

@router.post("/scan", response_model=URLScanResponse)
def scan_url(request: URLScanRequest, db: Session = Depends(get_db)):
    # Scan the URL
    scan_result = url_scanner.scan_url(request.url)
    
    # Create database record
    db_scan = URLScan(
        url=request.url,
        is_malicious=scan_result["is_malicious"],
        risk_score=scan_result["risk_score"],
        scan_result=scan_result["scan_result"]
    )
    
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    return URLScanResponse(
        url=db_scan.url,
        is_malicious=db_scan.is_malicious,
        risk_score=db_scan.risk_score,
        scan_result=db_scan.scan_result,
        scan_date=db_scan.scan_date
    )

@router.post("/scan/qr", response_model=QRScanResponse)
async def scan_qr_code(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload and scan a QR code image.
    The QR code should contain a URL which will be analyzed for phishing threats.
    """
    try:
        contents = await file.read()
        result = qr_scanner.scan_qr_code(contents)
        
        if result["success"] and result["scan_result"]:
            # Save to database if URL was found and scanned
            db_scan = URLScan(
                url=result["url"],
                is_malicious=result["scan_result"]["is_malicious"],
                risk_score=result["scan_result"]["risk_score"],
                scan_result=result["scan_result"]["scan_result"]
            )
            db.add(db_scan)
            db.commit()
        
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/history", response_model=List[URLScanResponse])
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(URLScan).order_by(URLScan.scan_date.desc()).limit(100).all()
    return scans 