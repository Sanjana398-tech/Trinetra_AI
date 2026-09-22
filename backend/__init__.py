"""
TRINETRA AI - Backend Application Package
==========================================
Application factory for the Flask app. Keeps app.py minimal and
allows the backend to be imported/tested as a proper Python package.
"""

import os
import logging

from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS

load_dotenv()  # populate os.environ from a local .env file, if present

from backend.config import get_config
from backend.extensions import db, login_manager, csrf
from backend.utils.localization import (
    SUPPORTED_LANGUAGES,
    DEFAULT_LANGUAGE,
    normalize_language,
    translate,
    localize_result,
)


def create_app(config_name: str = None) -> Flask:
    """
    Application factory.

    Creates and configures the Flask application instance, initializes
    extensions (database, login, CSRF), registers blueprints (route
    modules), and sets up global error handlers.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join("..", "frontend", "templates"),
        static_folder=os.path.join("..", "frontend", "static"),
        static_url_path="/static",
    )

    # ---- Configuration -------------------------------------------------
    app.config.from_object(get_config(config_name))

    @app.before_request
    def select_language():
        session["language"] = normalize_language(session.get("language", DEFAULT_LANGUAGE))

    @app.context_processor
    def localization_context():
        language = session.get("language", DEFAULT_LANGUAGE)
        return {
            "language": language,
            "languages": SUPPORTED_LANGUAGES,
            "_": lambda value: translate(value, language),
            "translate": lambda value: translate(value, language),
        }

    @app.template_filter("verdict_label")
    def verdict_label(value):
        return translate(value, session.get("language", DEFAULT_LANGUAGE))

    @app.template_filter("translate")
    def translate_filter(value):
        return translate(value, session.get("language", DEFAULT_LANGUAGE))

    @app.template_filter("translate_result")
    def translate_result(value):
        return localize_result(value, session.get("language", DEFAULT_LANGUAGE))

    @app.route("/language/<language>")
    def set_language(language):
        session["language"] = normalize_language(language)
        referrer = request.referrer
        if referrer and referrer.startswith(request.host_url):
            return redirect(referrer)
        return redirect(url_for("dashboard.dashboard"))

    @app.route("/")
    def landing():
        return render_template("landing.html", page_title="Cyber Scam Defense")

    # Trust one hop of X-Forwarded-* headers from the platform's reverse
    # proxy (Render, Heroku, etc.) so url_for(_external=True), request.scheme,
    # and secure-cookie checks behave correctly behind HTTPS termination.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # ---- CORS for Secure Chat integration ---------------------------------
    # Allow the Secure Chat backend (localhost:3000) to call the analysis API.
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ],
            "methods": ["POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
        }
    })

    # ---- Logging ---------------------------------------------------------
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if app.config.get("ENV") == "production" and app.config["SECRET_KEY"] == "dev-insecure-key-change-me":
        app.logger.warning(
            "SECRET_KEY is still the insecure default in a production environment! "
            "Set a real SECRET_KEY via environment variable before deploying."
        )

    # ---- Extensions ------------------------------------------------------
    db.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to continue."
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        from backend.db_models import User
        return db.session.get(User, int(user_id))

    # ---- Blueprints (route modules) --------------------------------------
    from backend.routes.auth import auth_bp
    from backend.routes.dashboard import dashboard_bp
    from backend.routes.history import history_bp
    from backend.routes.message_scan import message_scan_bp
    from backend.routes.url_scan import url_scan_bp
    from backend.routes.qr_scan import qr_scan_bp
    from backend.routes.voice_scan import voice_scan_bp
    from backend.routes.screenshot_scan import screenshot_scan_bp
    from backend.routes.upi_scan import upi_scan_bp
    from backend.routes.knowledge import knowledge_bp
    from backend.routes.reports import reports_bp
    from backend.routes.api import api_bp
    from backend.routes.analytics import analytics_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(message_scan_bp)
    app.register_blueprint(url_scan_bp)
    app.register_blueprint(qr_scan_bp)
    app.register_blueprint(voice_scan_bp)
    app.register_blueprint(screenshot_scan_bp)
    app.register_blueprint(upi_scan_bp)
    app.register_blueprint(knowledge_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp)

    # Exempt the API blueprint from CSRF (server-to-server calls from Secure Chat)
    csrf.exempt(api_bp)

    # ---- Database bootstrap -----------------------------------------------
    with app.app_context():
        from backend import db_models  # noqa: F401  (registers models with SQLAlchemy)
        db.create_all()

        # ``create_all`` does not update tables that already exist. Add fields
        # introduced after the initial local database schema was created.
        scan_history_columns = {
            column["name"]
            for column in db.inspect(db.engine).get_columns("scan_history")
        }
        if "source" not in scan_history_columns:
            db.session.execute(db.text(
                "ALTER TABLE scan_history "
                "ADD COLUMN source VARCHAR(50) NOT NULL DEFAULT 'web'"
            ))
        if "external_user_id" not in scan_history_columns:
            db.session.execute(db.text(
                "ALTER TABLE scan_history "
                "ADD COLUMN external_user_id VARCHAR(150)"
            ))
        if (
            "source" not in scan_history_columns
            or "external_user_id" not in scan_history_columns
        ):
            db.session.commit()

        from backend.utils.seed import purge_demo_scans, seed_demo_data

        # Remove legacy Phase-1 demo rows so analytics reflect real scans only.
        purge_demo_scans()
        # Optional demo seed (off by default; set SEED_DEMO=1 to enable).
        seed_demo_data()

        # Database migration: lowercase all existing verdicts in ScanHistory
        from backend.db_models import ScanHistory
        try:
            all_scans = ScanHistory.query.all()
            dirty = False
            for s in all_scans:
                if s.verdict and s.verdict != s.verdict.lower():
                    s.verdict = s.verdict.lower()
                    dirty = True
            if dirty:
                db.session.commit()
                app.logger.info("Migrated ScanHistory verdicts to lowercase for dashboard compatibility.")
        except Exception as e:
            app.logger.error(f"Error during ScanHistory verdict migration: {e}")

    # ---- Health check (for deployment platforms / uptime monitors) --------
    @app.route("/healthz")
    def healthz():
        try:
            db.session.execute(db.text("SELECT 1"))
            db_ok = True
        except Exception:  # noqa: BLE001
            db_ok = False
        status = "ok" if db_ok else "degraded"
        return jsonify(status=status, database=db_ok), (200 if db_ok else 503)

    # ---- Global error handlers --------------------------------------------
    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def file_too_large(_error):
        return render_template("errors/413.html"), 413

    @app.errorhandler(500)
    def server_error(_error):
        app.logger.exception("Internal server error")
        return render_template("errors/500.html"), 500

    return app
