<div align="center">

# CaughtPhish

**Real-time phishing URL detection powered by machine learning**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![CatBoost](https://img.shields.io/badge/CatBoost-1.2.10-yellow?logo=yandex&logoColor=white)](https://catboost.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Model Version](https://img.shields.io/badge/Model-v3.1-orange)]()
[![Dataset](https://img.shields.io/badge/Training%20URLs-452%2C163-red)]()

</div>

---

## 🔗 Live Demo
**[https://your-render-url.onrender.com](https://phishing-url-detector-jhyb.onrender.com/)**

## What is CaughtPhish?

CaughtPhish is a web-based phishing URL detector that scores any URL across **22 heuristic features** in real time and returns a verdict `PHISHING` or `LEGITIMATE` along with a threat confidence score and a ranked list of flagged indicators.

Under the hood it runs a **CatBoost gradient-boosted classifier** trained on 452,163 URLs labeled URLs. The feature extraction pipeline analyzes structural URL signals digit ratios, subdomain depth, suspicious keywords, hostname patterns, and more before scoring.

The project ships with a terminal-themed Flask web UI named **CaughtPhish** and a modular Python package you can import directly.

---

## Demo

```
> TARGET URL
https://paypal-verify.account-secure.com/login?user=victim&confirm=true

▌ PHISHING             Threat Score: 0.9741
─────────────────────────────────────────────────────────
TRIGGERED FLAGS (6)

[HIGH]  Hyphen in Domain      Domain contains a hyphen, often used to mimic 
                  legitimate brands (e.g. paypal-verify.com)
[HIGH]  Suspicious Keywords    URL contains words like "login", "verify", or 
                  "secure" commonly used in phishing
[HIGH]  TLD in Subdomain      A top-level domain (.com, .net) appears in the 
                  subdomain a known phishing trick
[HIGH]  Multiple .com Occurrences URL contains .com more than once
[MEDIUM] Long URL          URL is unusually long
[MEDIUM] High Digit Ratio      URL contains an unusually high proportion of numbers
```

---

## Features

**Detection Engine**
- CatBoost classifier trained on 828,851 URLs (phishing + legitimate)
- 22-feature extraction pipeline built entirely on URL structural signals
- Per-prediction explainability every verdict shows which features triggered and why
- Severity-ranked flag list: `high`, `medium`, `low`

**Web Interface (CaughtPhish)**
- Terminal-style dark UI, no JavaScript framework required
- Live scanning via `fetch` POST to `/predict`
- Confidence score, verdict badge, timestamp, and flag list on every result
- Graceful error states and a VirusTotal/PhishTank disclaimer

**Engineering**
- Modular `src/` package with separate feature extractor, exception handler, and logger
- Threshold-based flag logic tuned per feature not a one-size-fits-all cutoff
- Procfile included for one-command deployment on Render

---

## Project Structure

```
phishing-url-detector/
│
├── app/
│  ├── app.py         # Flask app, /predict route, flag logic
│  ├── static/
│  │  ├── style.css      # Terminal-themed UI styles
│  │  └── script.js      # Async scan handler
│  └── templates/
│    └── index.html     # CaughtPhish UI
│
├── model/
│  ├── phishing_model.pkl   # Trained CatBoost model (v3.1)
│  └── feature_cols.pkl    # Ordered feature column list
│
├── notebooks/
│  ├── 01_EDA.ipynb      # Exploratory data analysis
│  └── 02_Training.ipynb    # Model training, evaluation, export
│
├── src/
│  ├── feature_extractor.py  # URL feature extraction (22 features)
│  ├── exception.py      # Custom exception with traceback detail
│  ├── logger.py        # Timestamped file-based logging
│  ├── components/
│  │  ├── data_ingestion.py
│  │  ├── data_transformation.py
│  │  └── model_trainer.py
│  └── pipeline/
│    ├── train_pipeline.py
│    └── predict_pipeline.py
│
├── Procfile          # web: python app/app.py
├── requirements.txt
└── setup.py
```

---

## Feature Set

The classifier scores every URL across these 22 signals:

| Feature | Type | Severity | Description |
|---|---|---|---|
| `ip` | Binary | High | Raw IP address used instead of domain name |
| `phish_hints` | Count | High | Suspicious keywords: `login`, `verify`, `secure`, `paypal`, `account`, etc. |
| `prefix_suffix` | Binary | High | Hyphen present in hostname |
| `tld_in_subdomain` | Binary | High | TLD (`.com`, `.net`) appears inside a subdomain |
| `nb_com` | Count | High | `.com` appears more than once in the URL |
| `ratio_digits_url` | Float | Medium | Proportion of digits to alpha characters in full URL |
| `ratio_digits_host` | Float | Medium | Same ratio, hostname only |
| `length_url` | Int | Medium | Full URL length (flag if > 75 chars) |
| `nb_dots` | Count | Medium | Total `.` count (flag if > 4) |
| `nb_slash` | Count | Medium | Total `/` count (flag if > 5) |
| `length_hostname` | Int | Medium | Hostname character length |
| `nb_qm` | Count | Low | Number of `?` characters |
| `nb_eq` | Count | Low | Number of `=` characters |
| `nb_and` | Count | Low | Number of `&` characters |
| `nb_www` | Count | Low | Absence of `www` in the URL |
| `shortest_word_host` | Int | Low | Length of shortest token in hostname |
| `longest_word_path` | Int | Low | Length of longest token in path |
| `longest_words_raw` | Int | Low | Longest token across entire URL |
| `avg_word_path` | Float | Low | Average token length in path |
| `avg_word_host` | Float | Low | Average token length in hostname |
| `length_words_raw` | Int | Low | Total character count of all URL tokens |
| `avg_words_raw` | Float | Low | Average token length across entire URL |

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | CatBoost 1.2.10 |
| Feature Extraction | Python `urllib`, `re` |
| Web Framework | Flask 3.1.3 |
| Data / EDA | Pandas 3.0.3, NumPy 2.4.6, Matplotlib, Seaborn, Plotly |
| Model Serialization | `joblib` |
| Deployment | Procfile (Render) |

---

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/gritzoogil/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt
```

### 2. Run the web app

```bash
python app/app.py
```

Open `http://localhost:5000` in your browser. Paste any URL and click **SCAN**.

### 3. Call the API directly

```bash
curl -X POST http://localhost:5000/predict \
 -H "Content-Type: application/json" \
 -d '{"url": "https://paypal-verify.account-secure.com/login"}'
```

**Response:**

```json
{
 "verdict": "PHISHING",
 "confidence": 0.9741,
 "features": [
  {
   "name": "Hyphen in Domain",
   "description": "Domain contains a hyphen, often used to mimic legitimate brands.",
   "severity": "high"
  },
  {
   "name": "Suspicious Keywords",
   "description": "URL contains words like 'login', 'verify', or 'secure'.",
   "severity": "high"
  }
 ]
}
```

### 4. Use the Python package

```python
from src.feature_extractor import get_all_features, FEATURE_COLS
import joblib

model = joblib.load('model/phishing_model.pkl')

url = "https://example-login.verify-now.com/secure"
features = get_all_features(url)
prediction = model.predict([features])[0]
confidence = model.predict_proba([features])[0][1]

print("PHISHING" if prediction == 1 else "LEGITIMATE", f"({confidence:.2%})")
```

---

## API Reference

### `POST /predict`

Scores a URL and returns a verdict with explainability flags.

**Request body**

```json
{
 "url": "https://target-url.com/path"
}
```

**Response (200)**

| Field | Type | Description |
|---|---|---|
| `verdict` | `string` | `"PHISHING"` or `"LEGITIMATE"` |
| `confidence` | `float` | Probability (0–1) that the URL is phishing |
| `features` | `array` | List of triggered flags, sorted by severity |

Each flag object:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Short flag label |
| `description` | `string` | Plain-English explanation |
| `severity` | `string` | `"high"`, `"medium"`, or `"low"` |

**Error response (400)**

```json
{ "error": "No URL provided." }
```

---

## Model Details

The classifier was trained and evaluated in `notebooks/02_Training.ipynb`.

- **Algorithm:** CatBoost (gradient-boosted decision trees)
- **Training set:** 452,163 URLs
- **Features:** 22 (URL-structural signals only)
- **Model file:** `model/phishing_model.pkl` (~12 MB)
- **Feature list:** `model/feature_cols.pkl`

CatBoost handles mixed numerical features without preprocessing and trains fast on tabular data without feature scaling. These properties made it a practical fit for this feature set.

> **Note:** No ground-truth accuracy figures are hardcoded here because they depend on the exact train/test split and dataset version used in the notebook. Run `02_Training.ipynb` to reproduce evaluation metrics on your environment.

---

## Deployment

The `Procfile` targets any platform that reads it:

```
web: python app/app.py
```

The app binds to `0.0.0.0` on `$PORT` (falls back to `5000`):

```python
app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
```

**Render**

Push the repo, set the start command to `python app/app.py`, and the platform picks up `$PORT` automatically.

**Docker (minimal example)**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "app/app.py"]
```

---

## Limitations

CaughtPhish scores URLs based on structural signals it does not visit or render the page. This has practical consequences worth knowing:

- Phishing pages hosted at short, clean paths on compromised legitimate domains may score lower than they deserve.
- Highly obfuscated URLs that avoid common structural tells (hyphens, digit padding, keyword stuffing) can slip through.
- The model does not evaluate page content, SSL certificate validity, or visual similarity to known brands.

For high-stakes decisions, cross-check results with [VirusTotal](https://www.virustotal.com) or [PhishTank](https://phishtank.org).

---

## Contributing

Pull requests are welcome. To add a new heuristic feature:

1. Add the extraction logic to `src/feature_extractor.py` and append the column name to `FEATURE_COLS`.
2. Add a threshold entry to `THRESHOLDS` in `app/app.py`.
3. Add a plain-English explanation to `FEATURE_EXPLANATIONS`.
4. Retrain the model via `notebooks/02_Training.ipynb` and replace `model/phishing_model.pkl`.

---

## Authors

| Name | Email | Role |
|---|---|---|
| Gil Guillermo | [guillermoocinagil@gmail.com](mailto:guillermoocinagil@gmail.com) | Lead Developer |
| Kent Ian Ramirez | [ramirezkentian0@gmail.com](mailto:ramirezkentian0@gmail.com) | Cybersecurity Analyst |

---

## License

```
MIT License

Copyright (c) 2026 gil

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Disclaimer

CaughtPhish is a research and educational tool. It is not a replacement for dedicated security software. The authors make no guarantees of detection accuracy and accept no liability for decisions made based on its output.
