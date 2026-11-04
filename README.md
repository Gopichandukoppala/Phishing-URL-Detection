
# Phishing URL Detector

A machine learning-based web application that detects phishing websites by analyzing URL, domain, HTTPS, webpage content, and reputation-based features.

## Tech Stack

- **Frontend:** React, TypeScript, Vite, CSS
- **Backend:** Python, FastAPI
- **Machine Learning:** Scikit-learn, Random Forest Classifier
- **Data Processing:** Pandas, NumPy, BeautifulSoup
- **External Services:** RDAP, Tranco, OpenPhish, URLhaus, Google Custom Search, OpenPageRank

## Project Structure

```text
Phishing-URL-Detector/
│
├── backend/
│   ├── models/
│   │   └── RandomForest.pickle.dat
│   ├── app.py
│   ├── feature_extraction.py
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── index.css
│   │   ├── main.tsx
│   │   └── types.ts
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
│
├── ml/
│   ├── dataset.csv
│   └── Phishing_URL_Detection_ML.ipynb
│
└── README.md
```

## Features

- URL-based phishing detection.
- Extraction of 30 URL and webpage features.
- Random Forest machine learning classification.
- Website and SSL certificate analysis.
- Domain age and DNS verification.
- Detection using external phishing feeds.
- Feature-wise prediction details.
- REST API using FastAPI.

## Machine Learning

The project compares multiple algorithms, including:

- Random Forest
- Decision Tree
- Logistic Regression
- XGBoost
- Support Vector Machine
- Neural Network

The deployed model is a **Random Forest Classifier** trained using a stratified 80:20 train-test split.

### Random Forest Performance

| Metric | Score |
|---|---:|
| Accuracy | 93.08% |
| Precision | 94.25% |
| Recall | 92.22% |
| F1 Score | 93.22% |
| ROC-AUC | 97.93% |

The extractor calculates 30 features. The saved model uses 29 features, excluding `Links_pointing_to_page`.

### Prediction Labels

- `1` → Phishing (internal model class)
- `0` → Legitimate (internal model class)

The API converts these into:
- `phishing`
- `legitimate`

A phishing probability of 0.5 or higher produces a phishing verdict.

## Installation & Execution

### 1. Clone Repository

```bash
git clone <repository-url>
cd Phishing-URL-Detector
```

### 2. Start Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 3. Start Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

### 4. Open Application

Open the frontend URL displayed by Vite in your terminal.

Backend API documentation:

```text
http://127.0.0.1:8000/docs
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Check API status |
| POST | `/api/predict` | Predict URL classification |

### Prediction Request

```json
{
  "url": "https://example.com"
}
```

## Important Notes

- The backend requires the trained Random Forest pickle file.
- The dataset is used for aligning extracted features with training values.
- Some reputation features depend on external services and API credentials.
- The application requires internet access to inspect public websites.
- Predictions are machine learning estimates, not guarantees of website safety.

## Disclaimer

This project is developed for educational and research purposes. Always verify suspicious websites using additional security tools before interacting with them.
