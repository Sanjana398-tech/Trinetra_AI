# TRINETRA AI
### Smart Third-Eye Cyber Scam Detection System

A modern, AI-powered cybersecurity web application that analyzes suspicious
content across multiple channels — SMS, Email, WhatsApp, URLs, QR codes,
voice calls, and payment screenshots — and classifies it as **Safe**,
**Suspicious**, or **Scam**, with a plain-language explanation and
cybersecurity recommendations.

Built as a final-year engineering project with a production-quality,
modular Flask architecture.

---

## Build status — Phase 7 of N (all planned work complete)

This repository was built **incrementally, one phase at a time**.
Each phase was fully runnable before the next began.

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 1** | Project structure, Flask backend, database, navigation shell, dashboard UI | ✅ **Complete** |
| **Phase 2** | Scan History module + full CRUD on real scan records | ✅ **Complete** |
| **Phase 3** | Message Scam Detection (TF-IDF + ML) & URL Phishing Detection | ✅ **Complete** |
| **Phase 4** | QR Code Scanner & Voice Scam Detection (Whisper) | ✅ **Complete** |
| **Phase 5** | Fake Payment Screenshot Detection (OCR) | ✅ **Complete** |
| **Phase 6** | Cyber Safety Knowledge Hub & PDF Report Generator | ✅ **Complete** |
| **Phase 7** | Authentication, light mode, deployment hardening | ✅ **Complete** |

All 9 modules from the original project spec are real, working features, and the app now
has real user accounts, a working light theme, and production-oriented configuration.

---

## Tech Stack

**Frontend:** HTML5, CSS3 (custom design system with dark + light themes, no framework), Vanilla JS, Chart.js
**Backend:** Python 3.10+, Flask (application-factory pattern, Blueprints)
**Auth & Security:** Flask-Login (sessions), Flask-WTF (CSRF protection), Werkzeug password hashing
**Database:** SQLite via SQLAlchemy (swappable for Postgres/MySQL in production)
**Machine Learning:** Scikit-learn (TF-IDF + Logistic Regression for messages, Random Forest for
URLs), Pandas/NumPy for data handling, NLTK's PorterStemmer for text normalization
**QR Decoding:** OpenCV's built-in `QRCodeDetector` (no pyzbar/libzbar system dependency)
**Speech Recognition:** OpenAI Whisper (local, no cloud API)
**OCR:** Tesseract via pytesseract, for payment screenshot field extraction
**Reporting:** ReportLab for in-memory PDF generation (no files written to disk)
**Deployment:** Gunicorn, Procfile + runtime.txt (Render/Heroku-compatible), ProxyFix for
reverse-proxy deployments, `/healthz` endpoint

---

## Folder Structure

```
trinetra-ai/
├── app.py                     # Entry point (flask run / gunicorn target)
├── requirements.txt
├── Procfile                    # Render/Heroku deployment (Phase 7)
├── runtime.txt                 # Python version pin for deployment platforms
├── .env.example
├── .gitignore
│
├── backend/                   # Flask application package
│   ├── __init__.py            # App factory (create_app)
│   ├── config.py              # Environment-driven configuration
│   ├── extensions.py          # Flask extension instances (db, login_manager, csrf)
│   ├── db_models.py           # SQLAlchemy models
│   ├── routes/                # Blueprints (one file per feature area)
│   │   ├── auth.py            # Signup / login / logout (Phase 7)
│   │   ├── dashboard.py
│   │   ├── history.py         # Scan History CRUD (Phase 2)
│   │   ├── message_scan.py    # Message Scam Detection (Phase 3)
│   │   ├── url_scan.py        # URL Phishing Detection (Phase 3)
│   │   ├── qr_scan.py         # QR Code Scanner (Phase 4)
│   │   ├── voice_scan.py      # Voice Scam Detection (Phase 4)
│   │   ├── screenshot_scan.py # Fake Payment Screenshot Detection (Phase 5)
│   │   ├── knowledge.py       # Cyber Safety Knowledge Hub (Phase 6)
│   │   └── reports.py         # PDF Report Generator (Phase 6)
│   └── utils/                 # Backend-internal helpers
│       ├── seed.py              # Demo-data seeding (dashboard preview)
│       ├── scan_visibility.py   # Scopes ScanHistory queries to the current user (Phase 7)
│       ├── model_loader.py      # Lazy/cached .pkl loading with graceful fallback
│       ├── text_preprocess.py   # Shared message cleaning (train + serve)
│       ├── url_features.py      # Shared URL feature extraction (train + serve)
│       ├── message_reasons.py   # Rule-based "why" explanations for messages
│       ├── classifiers.py       # Shared classify_message()/classify_url() used by 4 routes
│       ├── qr_decode.py         # QR decoding (OpenCV)
│       ├── voice_transcribe.py  # Whisper transcription with graceful fallback
│       ├── screenshot_analyze.py # OCR extraction + rule-based fraud indicators
│       ├── knowledge_content.py  # Static Knowledge Hub article data
│       └── report_generator.py   # In-memory PDF generation (ReportLab)
│
├── frontend/
│   ├── templates/             # Jinja2 templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── auth/                (login, signup — Phase 7)
│   │   ├── history/            (list, detail, form — Phase 2)
│   │   ├── scan/                (message, url, qr, voice, screenshot — Phase 3/4/5)
│   │   ├── knowledge/           (hub, article — Phase 6)
│   │   ├── reports/             (list — Phase 6)
│   │   ├── errors/             (404 / 413 / 500)
│   │   └── partials/           (sidebar, topbar, icon macro)
│   └── static/
│       ├── css/                (tokens, base, layout, components, forms, scan, knowledge, auth, dashboard, background)
│       ├── js/                 (main.js, dashboard.js)
│       └── images/
│
├── uploads/                   # User-uploaded files (screenshots, audio) — gitignored contents
├── datasets/                  # Training datasets for message/URL models (generated)
├── models/                    # Trained .pkl models loaded at runtime
├── training/                  # Dataset generation + model training scripts
├── utils/                     # Standalone project-level scripts (non-Flask)
├── database/                  # SQLite database file lives here
└── docs/                      # Additional documentation
```

---

## Installation

**Prerequisites:** Python 3.10+ and `pip`.

```bash
# 1. Clone / enter the project
cd trinetra-ai

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env            # edit values if needed

# 5. Run the app
python app.py
```

The app starts at **http://localhost:5000**. On first run it automatically:
- creates `database/trinetra.db` and all tables,
- seeds a small, clearly-fake demo dataset visible to every account so the dashboard isn't
  empty on a fresh install (seeded once, when the table is empty).

Every functional page requires an account — you'll be redirected to **Sign Up** on first visit.
The Knowledge Hub (`/knowledge-hub`) is the only page that doesn't require login.

## Running with Gunicorn (production-style)

```bash
gunicorn -w 4 -b 0.0.0.0:8000 "app:app"
```

---

## What's in Phase 1

- ✅ Full modular folder structure (matches the spec above)
- ✅ Flask app factory with Blueprints, config classes, and error handlers (404/413/500)
- ✅ SQLite database via SQLAlchemy with 4 tables: `users`, `scan_history`, `reports`, `system_logs`
- ✅ Professional cybersecurity dashboard: live stats, 7-day threat trend chart, risk ring,
  channel breakdown, quick-scan tiles, filterable recent-scans table
- ✅ Fully wired sidebar navigation to every future module (placeholder screens, no dead links)
- ✅ Custom dark/blue-neon glassmorphism design system (no template starter-kit look)
- ✅ Responsive layout, keyboard focus states, `prefers-reduced-motion` support
- ✅ Upload-size limits & config pre-wired for later file-upload modules

## What's in Phase 2

- ✅ Real **Scan History** module (`backend/routes/history.py`) — replaces the Phase 1 placeholder
- ✅ Full CRUD on `ScanHistory` records:
  - **Create** — "Log a Scan" form (manual entry, standing in for the AI modules until Phase 3+ writes here automatically)
  - **Read** — paginated, searchable, filterable list + a full detail page per record
  - **Update** — edit form for verdict, scores, and explanation
  - **Delete** — with a confirmation prompt
- ✅ Search by input text, filter by channel and verdict, server-side pagination (10/page)
- ✅ Server-side form validation with inline field errors (no silent failures, no bad data saved)
- ✅ Every create/edit/delete action writes an audit entry to `system_logs`
- ✅ Flash-message system wired into the base layout for success/error feedback
- ✅ Dashboard's "Recent Scans" rows and "View All" link now point at real detail/list pages

## What's in Phase 3

- ✅ **Message Scam Detection** (`backend/routes/message_scan.py`) — TF-IDF + Logistic
  Regression classifier trained on a synthetic, template-based dataset (safe / suspicious / scam)
- ✅ **URL Phishing Detection** (`backend/routes/url_scan.py`) — Random Forest classifier over
  15 lexical/structural URL features (IP-as-domain, brand impersonation, suspicious TLDs,
  shorteners, hyphens, HTTPS presence, etc.) — no network calls, so scanning a URL never visits it
- ✅ Shared, train/serve-identical preprocessing modules so there's no skew between training and
  live inference: `backend/utils/text_preprocess.py` and `backend/utils/url_features.py`
- ✅ Rule-based explanation engines (`message_reasons.py`, `url_features.explain_reasons`) that
  turn the ML verdict into plain-English "why" reasons, plus verdict-appropriate safety tips
- ✅ `training/generate_datasets.py` — reproducible synthetic dataset generator
- ✅ `training/train_message_model.py` / `training/train_url_model.py` — training scripts that
  print accuracy, a classification report, and a confusion matrix, then save the `.pkl` files
- ✅ Graceful degradation: if a `.pkl` file is missing, the scan page still renders with a clear
  "model not trained yet" warning instead of crashing
- ✅ Every scan (message or URL) is saved to `ScanHistory` — dashboard stats and the Phase 2
  History CRUD screens now reflect real, model-generated predictions

### Training the models yourself

```bash
python training/generate_datasets.py     # creates datasets/messages_dataset.csv, urls_dataset.csv
python training/train_message_model.py   # -> models/message_model.pkl, models/tfidf_vectorizer.pkl
python training/train_url_model.py       # -> models/url_model.pkl
```

> **Note on the training data:** both datasets are synthetically generated from templates
> (see `training/generate_datasets.py`) rather than sourced from real scam reports, which is why
> reported test accuracy is very high — the templates used at train and test time share structure.
> This is appropriate for demonstrating a working end-to-end ML pipeline in a final-year project;
> swap in a real labeled dataset (same two CSV columns) for production-grade accuracy without
> touching any other file.

## What's in Phase 4

- ✅ **QR Code Scanner** (`backend/routes/qr_scan.py`) — decodes an uploaded QR image locally
  with OpenCV's built-in `QRCodeDetector` (deliberately avoids the pyzbar/libzbar system
  dependency), then automatically routes the decoded content into the URL model if it looks
  like a link, or the Message model otherwise — so a QR containing plain scam text still gets
  analyzed sensibly, not just ones containing a URL
- ✅ **Voice Scam Detection** (`backend/routes/voice_scan.py`) — transcribes an uploaded call
  recording with Whisper (`backend/utils/voice_transcribe.py`), then classifies the transcript
  with the same Message Detection model used by Message Scan
- ✅ A "paste transcript" fallback on the Voice Scan form: if Whisper's model checkpoint hasn't
  been downloaded yet (needs internet on first use) or the package isn't installed, the
  scam-language analysis can still be tested directly on any transcript text — genuinely useful
  standalone, not just a workaround
- ✅ Refactored `backend/utils/classifiers.py` — `classify_message()` / `classify_url()` are now
  shared by all four scanning routes (Message, URL, QR, Voice) instead of duplicating the
  probability → confidence/risk math four times
- ✅ Uploaded images/audio are processed and then immediately deleted — nothing is retained on
  disk longer than the request that needs it
- ✅ Same graceful-degradation pattern as Phase 3: missing Whisper package, missing model
  checkpoint, or no internet on first run all show a friendly warning instead of a crash
  (verified directly — the sandbox this was built in has no internet path to download Whisper's
  checkpoint, so this fallback path is exercised for real, not simulated)

> **Note on Whisper:** `openai-whisper` pulls in PyTorch, a large dependency (500MB+ download).
> The model checkpoint itself (~75MB for the default `tiny` size) downloads from OpenAI's
> servers the first time it's used, so an internet connection is required on first run in
> whatever environment ultimately runs this app. `ffmpeg` must also be installed and on `PATH`.

## What's in Phase 5

- ✅ **Fake Payment Screenshot Detection** (`backend/routes/screenshot_scan.py`) — runs Tesseract
  OCR on an uploaded screenshot (`backend/utils/screenshot_analyze.py`), with light preprocessing
  (grayscale, autocontrast, upscaling) to improve accuracy on small/compressed images
- ✅ Parses five fields out of the OCR'd text: **amount, UPI ID, transaction ID/UTR, bank name,
  timestamp** — each shown clearly as "Not found" when absent rather than guessed at
- ✅ **No ML model here by design** — this is a transparent, rule-based scoring engine. It flags
  concrete text-pattern indicators (missing transaction ID, missing timestamp, unrecognized UPI
  handle suffix, "sample/test/demo" wording, contradictory status words like "success" + "failed"
  in the same image) and weighs them into a risk score and Safe/Suspicious/Scam verdict
- ✅ Verified against three synthetic test receipts: a complete genuine-looking one (→ **Safe**),
  one missing every identifying field with "sample test transaction" wording (→ **Scam**), and one
  with contradictory "Successful"/"Failed" status text (→ **Scam**) — all classified correctly
- ✅ Same upload validation, error handling, and immediate temp-file cleanup pattern as the other
  upload-based modules

> **Scope note:** this module does OCR + text-pattern analysis, not pixel-level image forensics
> (error-level analysis, EXIF/metadata inspection, font-consistency checks). A well-crafted fake
> that gets every text field "right" could still pass — that class of detection is a meaningfully
> different, image-forensics problem outside this module's scope. The text-pattern checks here
> catch the far more common case: hastily edited or incomplete fake screenshots.

## What's in Phase 6

- ✅ **Cyber Safety Knowledge Hub** (`backend/routes/knowledge.py`) — 6 educational articles
  covering UPI safety, OTP fraud, QR scam awareness, phishing awareness, password security, and
  general scam-pattern awareness. Content lives as plain Python data
  (`backend/utils/knowledge_content.py`), not a DB table, since it's editorial content that
  doesn't need CRUD — add a new article by adding one entry to a list
- ✅ **PDF Report Generator** (`backend/routes/reports.py`, `backend/utils/report_generator.py`)
  — generates a branded PDF (scan type, input, verdict, confidence, risk, reasons,
  recommendations, timestamps) for any `ScanHistory` record using ReportLab, entirely **in
  memory** — no file is ever written to disk, so there's nothing to clean up or accumulate
- ✅ A "Download PDF Report" button was added to every scan result page and to the Scan History
  detail page, plus a dedicated `/reports` list for browsing and downloading any past scan
- ✅ Verified the PDF actually renders correctly (converted to an image and visually inspected,
  not just checked for a 200 status) — confirmed branded header, verdict banner, extracted
  summary table, reasons, and recommendations all appear correctly
- ✅ **Removed the placeholder-module scaffolding entirely** (`backend/routes/modules.py` and
  `module_placeholder.html`) now that every module in the original spec is a real feature — no
  dead code or unused "coming soon" mechanism left behind
- ✅ Removed the unused top-level `reports/` directory and its config/gitignore references, since
  the design deliberately never writes PDFs to disk

## What's in Phase 7

- ✅ **User authentication** (`backend/routes/auth.py`) — signup, login, logout using
  Flask-Login for session management and Werkzeug's PBKDF2 password hashing (passwords are
  never stored or logged in plaintext). Every functional route (Dashboard, History, all 5 scan
  modules, Reports) now requires login; the Knowledge Hub stays public since it's educational
  content with nothing sensitive in it
- ✅ **Per-user data scoping** (`backend/utils/scan_visibility.py`) — each user sees their own
  scans plus the unowned demo/seed rows every fresh install ships with; History edit/delete is
  restricted to records the user actually owns
- ✅ **CSRF protection** via Flask-WTF, enabled globally — every POST form across the app (auth,
  History CRUD, all 5 scan uploads) carries a token; verified directly that a request with no
  token or a forged token is rejected with 400, while legitimate authenticated requests succeed
- ✅ **Light mode**, actually implemented — the theme toggle already existed in the topbar since
  Phase 1, but now flips a full set of CSS variables (surfaces, text, borders) via a
  `.light-mode` class, and the animated hex-grid/radar background is dialed down (not hidden)
  so it doesn't look noisy on a white background. Verdict colors are deepened slightly for
  contrast but kept recognizably the same hue in both themes
- ✅ **Deployment hardening**: `python-dotenv` is now actually loaded (`load_dotenv()` was
  wired into the app factory — previously the dependency was installed but never called!),
  `ProxyFix` middleware for correct scheme/host detection behind a reverse proxy, secure/HttpOnly/
  SameSite cookie flags (auto-relaxed for local HTTP dev, strict in production), a startup
  warning if `SECRET_KEY` is still the default in production, a `/healthz` endpoint, and a
  `Procfile` + `runtime.txt` for Render/Heroku-style deployment
- ✅ Verified end-to-end: signup → session cookie set → protected pages accessible → scan
  correctly attributed to that user → logout → protected pages redirect again; plus duplicate-
  email, weak-password, password-mismatch, and wrong-password validation all confirmed working

## All planned work is complete

Every module from the original project spec, plus authentication, theming, and deployment
readiness, is implemented and tested. The app is a complete, runnable, multi-user cybersecurity
scam-detection platform suitable for a final-year engineering demonstration.

---

## Deploying to Render (or similar platforms)

1. Push this repository to GitHub.
2. Create a new **Web Service** on Render, pointing at the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command is read automatically from `Procfile` (`gunicorn -w 4 -b 0.0.0.0:$PORT "app:app"`).
5. Set environment variables in Render's dashboard (mirror `.env.example`):
   - `FLASK_ENV=production`
   - `SECRET_KEY` — generate a real one, don't reuse the dev default
   - `DATABASE_URL` — point at a managed Postgres instance for anything beyond a demo (SQLite
     works but its file won't persist across deploys on most platforms' ephemeral filesystems)
6. Tesseract and ffmpeg need to be present in the deploy environment — Render's standard Python
   runtime doesn't include them by default; use a `Dockerfile` or Render's "native environment"
   apt-packages support if you need Voice/Screenshot scanning in production. Message, URL, QR,
   Knowledge Hub, and Reports work with no extra system packages.

## How to Train Models

```bash
python training/generate_datasets.py     # creates datasets/messages_dataset.csv, urls_dataset.csv
python training/train_message_model.py   # -> models/message_model.pkl, models/tfidf_vectorizer.pkl
python training/train_url_model.py       # -> models/url_model.pkl
```

Each script prints accuracy, a per-class precision/recall report, and a confusion matrix. Retrain
any time by re-running the relevant script — the Flask app loads models lazily and picks up new
files on the next restart.

## API Documentation

Not applicable yet — Phase 1 ships no JSON API endpoints, only server-rendered pages.
This section will be filled in as each module adds routes.

---

## License

Academic / educational project.

## Actual Folder Structure

```
trinetra-ai/
    .env
    .env.example
    .gitignore
    Procfile
    README.md
    app.py
    backend/
        __init__.py
        __pycache__/
            __init__.cpython-311.pyc
            config.cpython-311.pyc
            db_models.cpython-311.pyc
            extensions.cpython-311.pyc
        config.py
        db_models.py
        extensions.py
        routes/
            __init__.py
            __pycache__/
                __init__.cpython-311.pyc
                auth.cpython-311.pyc
                dashboard.cpython-311.pyc
                history.cpython-311.pyc
                knowledge.cpython-311.pyc
                message_scan.cpython-311.pyc
                qr_scan.cpython-311.pyc
                reports.cpython-311.pyc
                screenshot_scan.cpython-311.pyc
                url_scan.cpython-311.pyc
                voice_scan.cpython-311.pyc
            auth.py
            dashboard.py
            history.py
            knowledge.py
            message_scan.py
            qr_scan.py
            reports.py
            screenshot_scan.py
            url_scan.py
            voice_scan.py
        services/
            sms_service.py
        utils/
            __init__.py
            __pycache__/
                __init__.cpython-311.pyc
                classifiers.cpython-311.pyc
                knowledge_content.cpython-311.pyc
                message_reasons.cpython-311.pyc
                model_loader.cpython-311.pyc
                qr_decode.cpython-311.pyc
                report_generator.cpython-311.pyc
                scan_visibility.cpython-311.pyc
                screenshot_analyze.cpython-311.pyc
                seed.cpython-311.pyc
                text_preprocess.cpython-311.pyc
                url_features.cpython-311.pyc
                voice_transcribe.cpython-311.pyc
            classifiers.py
            distilbert_loader.py
            knowledge_content.py
            message_reasons.py
            model_loader.py
            qr_decode.py
            report_generator.py
            scan_visibility.py
            screenshot_analyze.py
            seed.py
            text_preprocess.py
            url_features.py
            voice_transcribe.py
            xgboost_loader.py
    database/
        trinetra.db
    datasets/
        .gitkeep
        messages_dataset.csv
        processed/
            final_messages.csv
            final_urls.csv
        raw/
            sms/
                spam.csv
            urls/
                legitimate_urls.csv
                phishing_urls.csv
        urls_dataset.csv
    docs/
        README.md
    frontend/
        static/
            css/
                auth.css
                background.css
                base.css
                components.css
                dashboard.css
                forms.css
                knowledge.css
                layout.css
                scan.css
                tokens.css
            images/
            js/
                dashboard.js
                main.js
        templates/
            auth/
                base_auth.html
                login.html
                signup.html
            base.html
            dashboard.html
            errors/
                404.html
                413.html
                500.html
            history/
                detail.html
                form.html
                list.html
            knowledge/
                article.html
                hub.html
            partials/
                icons.html
                sidebar.html
                topbar.html
            reports/
                list.html
            scan/
                message.html
                qr.html
                screenshot.html
                url.html
                voice.html
    models/
        .gitkeep
        config.json
        distilbert/
            config.json
            model.safetensors
            tokenizer.json
            tokenizer_config.json
        message_model.pkl
        model.safetensors
        tfidf_vectorizer.pkl
        tokenizer.json
        tokenizer_config.json
        url_model.pkl
        xgboost/
            url_model.json
    requirements.txt
    runtime.txt
    training/
        .gitkeep
        evaluate/
            evaluate_message.py
            evaluate_url.py
        generate_datasets.py
        notebooks/
        preprocess/
            clean_messages.py
            clean_urls.py
        train/
            train_distilbert.py
            train_xgboost.py
        train_message_model.py
        train_url_model.py
    uploads/
        .gitkeep
    utils/
        README.md
```

