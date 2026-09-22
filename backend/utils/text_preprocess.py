"""
TRINETRA AI - Text Preprocessing
===================================
Shared cleaning/tokenization pipeline for the Message Scam Detection
model. This module is imported by BOTH the training script
(training/train_message_model.py) and the live inference route
(backend/routes/message_scan.py) so the exact same transformation is
applied at train time and serve time.

Uses NLTK's PorterStemmer, which is a pure algorithmic stemmer and
needs no downloaded corpora — keeps the project fully offline-runnable.
A small hand-maintained stopword list is used instead of nltk's
downloadable 'stopwords' corpus for the same reason.
"""

import re

from nltk.stem import PorterStemmer

_stemmer = PorterStemmer()

# Compact English stopword list (hand-maintained, no download required).
STOPWORDS = frozenset("""
a an the and or but if while is are was were be been being
this that these those to of in on at for from with as by
it its it's i you he she we they me him her us them my your his
their our do does did doing have has had having not no nor so
than too very can will just don should now
""".split())

_URL_RE = re.compile(r"(https?://\S+|www\.\S+)")
_NON_ALPHA_RE = re.compile(r"[^a-z\s]")
_MULTISPACE_RE = re.compile(r"\s+")


def clean_text(raw_text: str) -> str:
    """
    Normalize raw message text into a clean, stemmed, space-joined
    token string ready for TF-IDF vectorization.

    Steps: lowercase -> replace URLs with a URL token (their presence
    is itself a strong signal) -> strip punctuation/numbers -> drop
    stopwords -> stem -> rejoin.
    """
    if not raw_text:
        return ""

    text = raw_text.lower()
    text = _URL_RE.sub(" linkurl ", text)
    text = _NON_ALPHA_RE.sub(" ", text)
    text = _MULTISPACE_RE.sub(" ", text).strip()

    tokens = [t for t in text.split(" ") if t and (t not in STOPWORDS) and (len(t) > 1)]
    stemmed = [_stemmer.stem(t) if t != "linkurl" else "linkurl" for t in tokens]
    return " ".join(stemmed)
