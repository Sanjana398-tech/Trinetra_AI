"""
TRINETRA AI - Authentication Routes
=======================================
Signup / login / logout. Passwords are hashed with Werkzeug's
generate_password_hash (PBKDF2) — never stored or logged in plaintext.
Forms are validated manually server-side (same style as the rest of
the app) rather than via WTForms field classes; CSRF protection is
still enforced globally through Flask-WTF's CSRFProtect.
"""

import re

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user

from backend.extensions import db
from backend.db_models import User, SystemLog

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        logout_user()

    errors = {}
    form_data = {"full_name": "", "email": ""}

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        form_data = {"full_name": full_name, "email": email}

        if not full_name:
            errors["full_name"] = "Please enter your name."
        if not email or not _EMAIL_RE.match(email):
            errors["email"] = "Please enter a valid email address."
        elif User.query.filter_by(email=email).first():
            errors["email"] = "An account with this email already exists."
        if len(password) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if password != confirm:
            errors["confirm_password"] = "Passwords don't match."

        if not errors:
            if current_user.is_authenticated:
                logout_user()
            user = User(full_name=full_name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.add(SystemLog(level="info", message=f"New account created: {email}", source="auth"))
            db.session.commit()

            login_user(user)
            flash(f"Welcome to TRINETRA AI, {full_name}!", "success")
            return redirect(url_for("dashboard.dashboard"))

        flash("Please fix the highlighted fields.", "error")

    return render_template("auth/signup.html", errors=errors, form_data=form_data)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))

    errors = {}
    form_data = {"email": ""}

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        form_data = {"email": email}

        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            errors["form"] = "Incorrect email or password."
        else:
            login_user(user, remember=True)
            db.session.add(SystemLog(level="info", message=f"Login: {email}", source="auth"))
            db.session.commit()
            flash(f"Welcome back, {user.full_name}!", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.dashboard"))

        flash("Please check your credentials and try again.", "error")

    return render_template("auth/login.html", errors=errors, form_data=form_data)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", "info")
    return redirect(url_for("auth.login"))
