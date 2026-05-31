# PhishGuard - Phishing Detection & Awareness Tool

## ICT942 Cybersecurity Project
**Master of Information Technology (MIT)**  
Semester S2 2025

---

## Overview

PhishGuard is an integrated cybersecurity solution that combines:
- **ML-powered phishing detection** for emails
- **Simulated phishing campaigns** for user training
- **Real-time analytics** for administrators

## Features

### 🔍 Phishing Detection Engine
- URL analysis and domain verification
- Content analysis for suspicious keywords
- Sender authentication checks
- Typosquatting detection
- Confidence scoring with explainable AI

### 🎓 User Awareness Training
- Simulated phishing email campaigns
- Interactive training modules
- Progress tracking and scoring
- Educational resources and quizzes

### 📊 Admin Dashboard
- Campaign management
- Real-time analytics
- User behavior tracking
- Detection performance metrics

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.9+, Flask |
| Database | SQLite (development) / MySQL (production) |
| ML Framework | scikit-learn, Random Forest |
| Frontend | HTML5, Bootstrap 5, JavaScript |
| Visualization | Chart.js |

---

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Step 1: Clone/Extract Project
```bash
cd phishing_detection_tool
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Initialize Database
```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Step 5: Train ML Model (Optional)
```bash
python train_model.py
```

### Step 6: Run Application
```bash
python app.py
```

The application will be available at: **http://localhost:5000**

---

## Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| User | (create via registration) | - |

---

## Project Structure

```
phishing_detection_tool/
├── app.py                 # Main Flask application
├── train_model.py         # ML model training script
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── models/               # Trained ML models
│   └── phishing_model.pkl
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── detect.html
│   ├── detection_result.html
│   ├── admin_dashboard.html
│   ├── user_dashboard.html
│   ├── campaigns.html
│   ├── create_campaign.html
│   ├── analytics.html
│   ├── simulation_email.html
│   ├── simulation_landing.html
│   └── training.html
└── static/              # Static assets (CSS, JS)
    ├── css/
    └── js/
```

---

## Usage Guide

### For Administrators:

1. **Login** with admin credentials
2. **Create Campaign**: Design phishing simulation campaigns
3. **Launch Campaign**: Send simulated phishing emails to users
4. **Monitor Analytics**: Track click rates, report rates, and improvement

### For Users:

1. **Register** for an account
2. **Check Simulations**: View assigned training emails in dashboard
3. **Analyze Emails**: Use detection tool to check suspicious emails
4. **Complete Training**: Learn from educational materials
5. **Report Phishing**: Flag suspicious emails correctly

---

## ML Detection Features

The system extracts 13 features from emails:

1. URL count
2. IP-based URLs
3. Suspicious TLDs (.tk, .ml, etc.)
4. Domain count
5. Misspelled domains (typosquatting)
6. Urgent language detection
7. Suspicious keywords
8. Exclamation mark count
9. Capital letter ratio
10. Numbers in sender address
11. Disposable email domains
12. Urgent subject lines
13. Exclamation in subject

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/detect` | POST | Analyze email for phishing |
| `/api/stats` | GET | Get system statistics |

### Example API Usage:

```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "test@example.com",
    "subject": "Test Subject",
    "content": "Email content here..."
  }'
```

---

## Security Considerations

- All passwords are hashed using Werkzeug
- Session management with Flask secret keys
- Input validation on all forms
- Protection against SQL injection via SQLAlchemy ORM
- CSRF protection recommended for production

---

## Future Enhancements

- [ ] Deep learning models (LSTM/CNN) for text analysis
- [ ] Browser extension for real-time email analysis
- [ ] Integration with email servers (Exchange, Gmail API)
- [ ] Advanced reporting with PDF export
- [ ] Multi-language phishing detection
- [ ] Mobile application

---

## License

Academic Project - Master of Information Technology

## Contact

For questions or issues, please contact the project team.

---

**Developed for ICT942 - Cybersecurity Project**
