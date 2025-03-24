import re
import requests
from typing import Dict, List
import os
from dotenv import load_dotenv
from PIL import Image
from pyzbar.pyzbar import decode
from io import BytesIO
import magic
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

load_dotenv()

class URLScanner:
    def __init__(self):
        self.google_safe_browsing_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "YOUR_API_KEY")
        self.safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.model = None
        self.model_path = "models/url_classifier.joblib"
        self.initialize_model()
        
    def initialize_model(self):
        """Initialize model with some training data or load existing model."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
            else:
                # Initialize with some example data
                X_train = self.get_initial_training_data()
                y_train = self.get_initial_training_labels()
                self.model = RandomForestClassifier(n_estimators=100)
                self.model.fit(X_train, y_train)
                # Save the trained model
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump(self.model, self.model_path)
        except Exception as e:
            print(f"Error initializing model: {str(e)}")
            self.model = None
            
    def get_initial_training_data(self) -> np.ndarray:
        """Get initial training data for the model."""
        # Example URLs for training
        safe_urls = [
            "https://www.google.com",
            "https://www.microsoft.com/account",
            "https://github.com/login",
            "https://www.amazon.com/signin",
            "https://www.paypal.com/signin"
        ]
        
        phishing_urls = [
            "https://login.secure-verification.xyz/auth",
            "http://paypal.secure-login.tk/verify",
            "https://account-verify-login.ml/secure",
            "http://banking-secure-login.ga/auth",
            "https://verification-account.cf/login"
        ]
        
        X = []
        for url in safe_urls + phishing_urls:
            features = self.extract_url_features(url)
            X.append(features[0])  # extract_url_features returns a 2D array
            
        return np.array(X)
        
    def get_initial_training_labels(self) -> np.ndarray:
        """Get labels for initial training data."""
        # 5 safe URLs and 5 phishing URLs
        return np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
            
    def extract_url_features(self, url: str) -> np.ndarray:
        """Extract features from URL for ML model."""
        features = {
            'length': len(url),
            'num_dots': url.count('.'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special': sum(not c.isalnum() for c in url),
            'has_https': int(url.startswith('https')),
            'num_directories': url.count('/'),
            'num_subdomains': url.count('.') - 1 if '.' in url else 0,
            'num_parameters': url.count('&') + (1 if '?' in url else 0),
        }
        return np.array([list(features.values())])
        
    def update_model(self, url: str, is_phishing: bool):
        """Update model with new data point if model exists."""
        if self.model is not None:
            try:
                features = self.extract_url_features(url)
                # Retrain model with new data
                X = np.vstack([features, self.get_initial_training_data()])
                y = np.append([int(is_phishing)], self.get_initial_training_labels())
                self.model.fit(X, y)
                joblib.dump(self.model, self.model_path)
            except Exception as e:
                print(f"Error updating model: {str(e)}")
    
    def _check_common_phishing_patterns(self, url: str) -> Dict:
        # High-risk patterns (each match adds 30 points)
        high_risk_patterns = [
            r'login|signin|account|verify|secure|banking|password',
            r'paypal|apple|google|microsoft|amazon|facebook|instagram',
            r'confirm|update|unlock|authenticate|recover',
            r'wallet|crypto|bitcoin|ethereum|binance'
        ]
        
        # Medium-risk patterns (each match adds 20 points)
        medium_risk_patterns = [
            r'(http|https)://[^/]+\.(xyz|tk|ml|ga|cf|gq|pw)',  # Suspicious TLDs
            r'\d{10,}',  # Long numbers
            r'[a-zA-Z0-9]{32,}',  # Long random strings
            r'redirect|return|callback'
        ]
        
        # Suspicious URL structure patterns (each match adds 25 points)
        structure_patterns = [
            r'([a-z0-9]+\.)*[a-z0-9]+\.[a-z]{2,}.*\1',  # Domain repetition
            r'[^/]+-[^/]+-[^/]+\.',  # Multiple hyphens
            r'bit\.ly|tinyurl|goo\.gl',  # URL shorteners
            r'@',  # @ symbol in URL
        ]
        
        risk_score = 0
        matches = []
        
        # Check high-risk patterns
        for pattern in high_risk_patterns:
            if re.search(pattern, url.lower()):
                risk_score += 30
                matches.append(f"High risk: {pattern}")
        
        # Check medium-risk patterns
        for pattern in medium_risk_patterns:
            if re.search(pattern, url.lower()):
                risk_score += 20
                matches.append(f"Medium risk: {pattern}")
        
        # Check structure patterns
        for pattern in structure_patterns:
            if re.search(pattern, url.lower()):
                risk_score += 25
                matches.append(f"Suspicious structure: {pattern}")
        
        # Additional checks
        if url.count('/') > 5:  # Complex path structure
            risk_score += 15
            matches.append("Complex URL structure")
            
        if url.count('?') > 1 or url.count('&') > 2:  # Multiple parameters
            risk_score += 15
            matches.append("Multiple query parameters")
            
        if len(url) > 100:  # Very long URL
            risk_score += 15
            matches.append("Unusually long URL")
                
        return {
            "risk_score": min(risk_score, 100),
            "matched_patterns": matches
        }
    
    def _check_google_safe_browsing(self, url: str) -> bool:
        if self.google_safe_browsing_api_key == "YOUR_API_KEY":
            return False
            
        payload = {
            "client": {
                "clientId": "qrphishing-scanner",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(
                f"{self.safe_browsing_url}?key={self.google_safe_browsing_api_key}",
                json=payload
            )
            return bool(response.json().get("matches"))
        except:
            return False
    
    def scan_url(self, url: str) -> Dict:
        # Basic pattern check
        pattern_results = self._check_common_phishing_patterns(url)
        risk_score = pattern_results["risk_score"]
        
        # ML-based prediction if model is available
        if self.model is not None:
            try:
                features = self.extract_url_features(url)
                ml_prob = float(self.model.predict_proba(features)[0][1])  # Convert numpy.float64 to Python float
                # Combine ML score with pattern-based score
                risk_score = (risk_score + ml_prob * 100) / 2
                pattern_results["matched_patterns"].append(f"ML Risk Score: {int(ml_prob * 100)}%")
            except Exception as e:
                print(f"Error in ML prediction: {str(e)}")
        
        # Google Safe Browsing check
        is_malicious = bool(self._check_google_safe_browsing(url))  # Convert numpy.bool_ to Python bool
        
        if is_malicious:
            risk_score = 100
            pattern_results["matched_patterns"].append("Flagged by Google Safe Browsing")
            
        # Determine scan result based on risk score
        if risk_score >= 80:
            scan_result = "Malicious"
        elif risk_score >= 50:
            scan_result = "Suspicious"
        else:
            scan_result = "Safe"
            
        # Update model with new data point
        self.update_model(url, bool(is_malicious or risk_score >= 80))  # Convert to Python bool
            
        return {
            "url": url,
            "is_malicious": bool(is_malicious or risk_score >= 80),  # Convert to Python bool
            "risk_score": int(risk_score),  # Convert numpy.int to Python int
            "matched_patterns": pattern_results["matched_patterns"],
            "scan_result": scan_result
        } 