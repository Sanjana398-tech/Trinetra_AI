"""
TRINETRA AI - Knowledge Hub Content
======================================
Static educational content for the Cyber Safety Knowledge Hub. Kept as
plain Python data (not DB-backed) since it's editorial content that
changes rarely and doesn't need CRUD — easy to extend by adding a new
entry to ARTICLES.
"""

ARTICLES = [
    {
        "slug": "upi-safety",
        "title": "UPI Safety: Protecting Your Payments",
        "icon": "shield",
        "category": "Payments",
        "summary": "The core rules that stop almost every UPI scam before it starts.",
        "read_time": "4 min read",
        "body": [
            ("Never share your UPI PIN",
             "Your UPI PIN is only ever needed to SEND money, never to receive it. "
             "Anyone asking for your PIN to 'complete' an incoming payment, refund, or "
             "cashback is trying to steal from your account."),
            ("Requests to receive money never need approval",
             "If someone sends you a 'collect request' or payment link and asks you to "
             "enter your PIN to accept money, that's a scam — legitimate incoming payments "
             "need no PIN at all."),
            ("Verify the payee name before paying",
             "Every UPI app shows the registered name of the person you're paying before "
             "you confirm. If it doesn't match who you think you're paying, stop and check."),
            ("Be wary of 'refund' and 'wrong transfer' calls",
             "A common scam: someone claims they sent money to you by mistake and asks you "
             "to 'return' it via a link or QR code they send. Always check your actual bank "
             "balance/statement first — don't trust their claim."),
            ("Screenshots are not proof of payment",
             "Payment screenshots can be edited. Always confirm money has actually arrived "
             "in your account or statement before releasing goods or services."),
        ],
    },
    {
        "slug": "otp-fraud",
        "title": "OTP Fraud: Why You Should Never Share It",
        "icon": "message-square",
        "category": "Authentication",
        "summary": "OTPs exist specifically so only you can approve an action — sharing one hands that control away.",
        "read_time": "3 min read",
        "body": [
            ("An OTP is proof of identity, not a customer service code",
             "Banks, delivery companies, and government agencies never call and ask you to "
             "'read out' the OTP you just received. If someone claiming to be from an "
             "organization asks for it, it's a scam."),
            ("OTPs are commonly requested during fake 'KYC update' calls",
             "A frequent pattern: a call claims your account/SIM/KYC needs urgent "
             "verification and asks for an OTP to 'confirm' your identity. This OTP is "
             "actually authorizing a transaction or SIM swap on your account."),
            ("Watch for OTPs you didn't request",
             "If you receive an OTP without initiating any action yourself, someone else is "
             "likely already trying to log in or transact using your details. Don't share it, "
             "and change your password/PIN immediately."),
            ("Time pressure is a red flag",
             "Scammers create urgency ('your OTP expires in 30 seconds, read it now!') to "
             "stop you from thinking it through. A genuine wait of a few seconds costs you "
             "nothing; sharing an OTP under pressure can cost you everything."),
        ],
    },
    {
        "slug": "qr-scam-awareness",
        "title": "QR Code Scams: What to Watch For",
        "icon": "qr-code",
        "category": "Payments",
        "summary": "Scanning a QR code to receive money is a myth that scammers exploit constantly.",
        "read_time": "3 min read",
        "body": [
            ("Scanning a QR code never gives you money",
             "QR codes are for SENDING/paying money, not receiving it. If someone asks you "
             "to scan a QR code and enter your PIN to 'receive' a payment/prize/refund, "
             "that QR is actually authorizing you to pay them."),
            ("Pasted-over or stuck-on QR codes at shops",
             "Physical QR codes at shops, parking stands, or donation boxes have been "
             "replaced with a scammer's own QR sticker in real reported cases. Verify the "
             "payee name shown after scanning before confirming any payment."),
            ("QR codes from unknown senders",
             "A QR code sent to you out of the blue (claiming to be a prize, refund, or "
             "job payment) should be treated the same as a suspicious link — don't scan it "
             "without a good reason to trust the sender."),
            ("Use TRINETRA's QR Scanner before acting on an unfamiliar code",
             "If a QR code's purpose or source is unclear, scan it through the QR Scanner "
             "module first to see what it actually decodes to before doing anything with it."),
        ],
    },
    {
        "slug": "phishing-awareness",
        "title": "Spotting Phishing Messages and Links",
        "icon": "link",
        "category": "Messaging",
        "summary": "Most phishing attempts share the same handful of tells once you know to look for them.",
        "read_time": "5 min read",
        "body": [
            ("Urgency and threats are the #1 tell",
             "'Your account will be suspended in 24 hours', 'final notice', 'act now' — "
             "phishing relies on panic to stop you from checking carefully. Genuine "
             "organizations give you reasonable time and multiple channels to respond."),
            ("Check the actual domain, not just the display text",
             "A link can display 'yourbank.com' while actually pointing anywhere. Hover "
             "over (don't click) links to preview the real destination, or type the known "
             "website address directly into your browser instead."),
            ("Look-alike domains",
             "Phishing domains often look almost right: extra hyphens, a different TLD "
             "(.tk, .xyz instead of .com), or a brand name plus an unrelated word "
             "(e.g. 'icicibank-verify.tk'). These are strong red flags."),
            ("Generic greetings on 'personal' messages",
             "'Dear Customer' or 'Dear valued user' instead of your actual name often "
             "signals a mass-sent scam template rather than a message really meant for you."),
            ("When in doubt, go direct",
             "Instead of clicking a link in a message, open the organization's official app "
             "or type their known website address yourself, and check your account there."),
        ],
    },
    {
        "slug": "password-security",
        "title": "Password & Account Security Basics",
        "icon": "settings",
        "category": "Account Security",
        "summary": "A few habits that make the vast majority of account takeovers far harder to pull off.",
        "read_time": "4 min read",
        "body": [
            ("Use a different password for every important account",
             "If one site is breached and you've reused that password elsewhere, attackers "
             "will try it on your email, banking, and social accounts automatically — this "
             "is called credential stuffing."),
            ("Turn on two-factor authentication (2FA)",
             "2FA means a stolen password alone isn't enough to log in. Prefer an "
             "authenticator app over SMS-based 2FA where possible, since SIM-swap fraud can "
             "intercept SMS codes."),
            ("Length beats complexity",
             "A long passphrase (e.g. four random unrelated words) is typically stronger "
             "and easier to remember than a short password with forced symbols."),
            ("Be suspicious of unexpected password-reset emails",
             "If you get a 'reset your password' email you didn't request, don't click it — "
             "someone may be trying to take over your account. Log in directly through the "
             "official site/app to check instead."),
            ("A password manager solves the 'remembering' problem",
             "It lets you use a strong, unique password everywhere without needing to "
             "memorize each one."),
        ],
    },
    {
        "slug": "scam-awareness-general",
        "title": "General Scam Awareness: The Patterns Behind the Tricks",
        "icon": "alert-triangle",
        "category": "General",
        "summary": "Nearly every scam — regardless of channel — leans on the same small set of psychological tricks.",
        "read_time": "5 min read",
        "body": [
            ("Urgency", "Rushing you so you act before you think it through."),
            ("Authority", "Impersonating a bank, government body, or company you trust to lower your guard."),
            ("Fear", "Threatening account loss, legal action, or arrest to provoke panic."),
            ("Greed / too-good-to-be-true offers", "Prizes, lottery wins, or unrealistic returns designed to override caution."),
            ("Isolation", "Discouraging you from 'telling anyone' or 'checking with your bank first' — a genuine "
                          "request never needs to be kept secret from people who could help you verify it."),
            ("The single best defense", "Slow down, verify independently through an official channel, and remember "
                                          "that legitimate organizations are always fine with you double-checking."),
        ],
    },
]

ARTICLE_IMAGES = {
    "upi-safety": "/static/images/knowledge/upi-safety.png",
    "otp-fraud": "/static/images/knowledge/otp-fraud.png",
    "qr-scam-awareness": "/static/images/knowledge/qr-scam-awareness.png",
    "phishing-awareness": "/static/images/knowledge/phishing-awareness.png",
    "password-security": "/static/images/knowledge/password-security.png",
    "scam-awareness-general": "/static/images/knowledge/scam-awareness-general.png",
}

for article in ARTICLES:
    article["image"] = ARTICLE_IMAGES.get(article["slug"], "")

BRIEFS = [
    {
        "label": "Voice scam watch",
        "date": "Safety brief",
        "title": "A familiar voice is not proof of identity",
        "summary": "Voice cloning can make a short scam call sound like someone you know. Hang up, then call the person back using a saved number.",
        "image": "/static/images/knowledge/brief-voice-scam.png",
        "action": "Remember: verify out of band",
    },
    {
        "label": "Payment safety",
        "date": "Safety brief",
        "title": "A QR code can send money, not receive it",
        "summary": "Scammers use refund and prize stories to make people scan a code. Check the payee name and never enter a PIN to receive money.",
        "image": "/static/images/knowledge/brief-payment-safety.png",
        "action": "Remember: scan, check, then decide",
    },
    {
        "label": "Phishing watch",
        "date": "Safety brief",
        "title": "Urgent KYC links are a common trap",
        "summary": "A message that threatens account closure pushes you to act quickly. Open the official banking app yourself instead of using its link.",
        "image": "/static/images/knowledge/brief-phishing-watch.png",
        "action": "Remember: go direct, never panic",
    },
]


def get_article(slug: str):
    return next((a for a in ARTICLES if a["slug"] == slug), None)
