# Anti-QRishing: QR Code Phishing Detection System

A cutting-edge system that detects hidden phishing threats in QR codes, protecting users from potential attacks. The system combines pattern matching, machine learning, and Google Safe Browsing API to provide comprehensive security analysis.

## Backend Setup

### Prerequisites
- Python 3.7 or higher
- MySQL Server
- pip (Python package installer)

### Installation Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd code/backend
   ```

2. **Create and activate virtual environment (recommended)**
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Database Setup**
   - Create a MySQL database named 'qrphishing'
   ```sql
   CREATE DATABASE qrphishing;
   ```
   - Configure database connection in `.env` file:
   ```env
   DATABASE_URL=mysql://root:your_password@localhost:3306/qrphishing
   GOOGLE_SAFE_BROWSING_API_KEY=YOUR_API_KEY
   ```

5. **Initialize the database**
   - The tables will be automatically created when you start the application

### Running the Backend Server

1. **Start the FastAPI server**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
   The server will start at `http://localhost:8000`

2. **API Endpoints**
   - `POST /api/v1/scan/qr` - Scan QR code image for phishing URLs
   - `POST /api/v1/scan` - Directly scan a URL for phishing threats
   - `GET /api/v1/history` - Get history of scanned URLs

### Testing the API

You can test the API using the provided Postman collection:
1. Import `Anti-QRishing.postman_collection.json` into Postman
2. Test the endpoints:
   - Use the "Scan QR Code" request to upload and scan QR code images
   - Use the "Scan URL" request to directly check URLs
   - Use the "Get Scan History" request to view scanning history

### Security Features

The system implements multiple layers of security:
- Pattern-based analysis for suspicious URL characteristics
- Machine Learning model for advanced threat detection
- Google Safe Browsing API integration (requires API key)
- Continuous learning from new scans
- Real-time risk assessment and scoring

### Response Format

The API returns detailed analysis results:
```json
{
    "success": true,
    "message": "QR code successfully scanned and analyzed.",
    "url": "https://example.com/login",
    "scan_result": {
        "url": "https://example.com/login",
        "is_malicious": false,
        "risk_score": 45,
        "matched_patterns": [
            "High risk: login pattern",
            "ML Risk Score: 30%"
        ],
        "scan_result": "Safe"
    }
}
```

## Frontend Setup

For Flutter frontend setup and instructions, please refer to the [Flutter Documentation](https://docs.flutter.dev/get-started/install).

1. Open folder frontend
   - Open via terminal cd frontend
   - Flutter pub get

2. Open file history_page.dart change apiurl with backend url 

3. Open file image_upload.dart in folder screens change apiurl with backend url

4. Open file qr_scanner.dart in folder screens change apiurl with backend url 

5. Running flutter via terminal : flutter run


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
