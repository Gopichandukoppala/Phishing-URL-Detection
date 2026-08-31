# Phishing URL Detector

Web app for the phishing-URL machine learning project. Paste a URL, extract the original 30 features, and classify the page with the saved linear SVM.

The UI is **React**. The API is **Python (FastAPI)** because `SVMClassifier.pickle.dat` is a scikit-learn pickle (Java cannot load it).

## Where the code is

| Path | What it is |
|---|---|
| `frontend/src/App.tsx` | Main React UI (form, verdict, feature grid) |
| `frontend/src/index.css` | Colors, fonts, page background |
| `frontend/index.html` | HTML shell |
| `backend/app.py` | FastAPI: URL checks, SVM predict, `/api/predict` |
| `backend/feature_extraction.py` | Your original 30-feature extractor |
| `backend/models/SVMClassifier.pickle.dat` | Trained linear SVM |
| `ml/Phishing_URL_Detection_ML.ipynb` | Training notebook |
| `ml/dataset.csv` | Training data |
| `run.sh` | Starts API + Vite together for local work |

The UI calls `POST /api/predict` with `{ "url": "..." }`. In development, Vite (port **43123**) proxies `/api` to FastAPI (port **43124**).

## Run locally

You need Python 3.11+ and Node.js 20+.

```bash
# Terminal 1 — API
cd backend
python3 -m pip install -r requirements.txt
python3 -m uvicorn app:app --host 0.0.0.0 --port 43124

# Terminal 2 — UI
cd frontend
npm install
npm run dev
```

Or from the repo root: `./run.sh`

Open http://127.0.0.1:43123

## Deploy (one server)

Build the React app, then let FastAPI serve the files from `frontend/dist` plus `/api`.

```bash
cd frontend
npm install
npm run build

cd ../backend
python3 -m pip install -r requirements.txt
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Open http://YOUR_SERVER:8000

The host must allow **outbound HTTP/HTTPS** so the extractor can download the submitted page.

### Docker

From the repo root:

```bash
docker build -t phishing-url-detector .
docker run --rm -p 8000:8000 phishing-url-detector
```

Then open http://127.0.0.1:8000

### Render / Railway / Fly

1. Connect this Git repository.
2. Use the Docker deploy, **or**:
   - **Build:** `cd frontend && npm ci && npm run build`
   - **Start:** `cd backend && uvicorn app:app --host 0.0.0.0 --port $PORT`
3. Set the start command to use `$PORT` (these hosts inject it).

Do not put the pickle file or the API on a static-only host (GitHub Pages, plain Netlify) unless you still run Python somewhere else. The model has to execute on a server.

## Labels

- original `Result = -1` → class `0` → phishing
- original `Result = 1` → class `1` → legitimate
- feature values: `1` legitimate, `0` suspicious, `-1` phishing

Domain age, WHOIS, PageRank, Google Index, and similar extractor fields are still placeholders.
