"""
TRINETRA AI - Extensions
=========================
Flask extension instances live here (not in __init__.py) so that models
and routes can import them without circular-import issues.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
