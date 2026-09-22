"""
TRINETRA AI - Cyber Safety Knowledge Hub Routes
===================================================
Serves the educational article listing and detail pages. Content is
static (see backend/utils/knowledge_content.py) — no DB table needed.
"""

from flask import Blueprint, render_template, abort

from backend.utils.knowledge_content import ARTICLES, BRIEFS, get_article

knowledge_bp = Blueprint("knowledge", __name__, url_prefix="/knowledge-hub")


@knowledge_bp.route("")
def hub():
    return render_template(
        "knowledge/hub.html",
        active_page="knowledge-hub",
        page_title="Cyber Safety Knowledge Hub",
        articles=ARTICLES,
        briefs=BRIEFS,
    )


@knowledge_bp.route("/<slug>")
def article(slug):
    art = get_article(slug)
    if art is None:
        abort(404)
    return render_template(
        "knowledge/article.html",
        active_page="knowledge-hub",
        page_title=art["title"],
        article=art,
    )
