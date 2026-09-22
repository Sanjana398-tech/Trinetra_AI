"""Centralized UI and scan-result localization for Trinetra AI."""

import re
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

SUPPORTED_LANGUAGES = {
    "en": "English",
    "hi": "हिन्दी",
    "kn": "ಕನ್ನಡ",
    "te": "తెలుగు",
    "ta": "தமிழ்",
    "ml": "മലയാളം",
}
DEFAULT_LANGUAGE = "en"
TRANSLATOR_LANGUAGE_CODES = {
    "en": "en", "hi": "hi", "kn": "kn", "te": "te", "ta": "ta", "ml": "ml",
}
_MYMEMORY_LANGUAGE_CODES = {
    "en": "en-GB", "hi": "hi-IN", "kn": "kn-IN", "te": "te-IN", "ta": "ta-IN", "ml": "ml-IN",
}

# Keep machine verdicts in English for CSS, APIs, storage, and model logic.
_TRANSLATIONS = {
    "en": {
        "safe": "SAFE", "suspicious": "SUSPICIOUS", "scam": "SCAM",
        "Confidence": "Confidence", "Risk Score": "Risk Score",
        "Why this verdict?": "Why this verdict?", "Recommended Actions": "Recommended Actions",
        "Probability": "Probability", "Safe": "Safe", "Scam": "Scam",
        "View Full Scan Record": "View Full Scan Record",
        "No common scam patterns detected in this message.": "No common scam patterns detected in this message.",
        "This message has characteristics worth double-checking.": "This message has characteristics worth double-checking.",
        "This message strongly matches known scam patterns. Do not act on it.": "This message strongly matches known scam patterns. Do not act on it.",
        "No common scam patterns detected in this message. Continue to stay cautious.": "No common scam patterns detected in this message. Continue to stay cautious.",
        "No common phishing indicators detected in this URL.": "No common phishing indicators detected in this URL.",
        "This URL has some characteristics worth double-checking.": "This URL has some characteristics worth double-checking.",
        "This URL strongly matches known phishing patterns. Do not enter any details.": "This URL strongly matches known phishing patterns. Do not enter any details.",
        "No common fraud indicators detected in this UPI request.": "No common fraud indicators detected in this UPI request.",
        "This UPI transaction has characteristics worth double-checking.": "This UPI transaction has characteristics worth double-checking.",
        "This UPI transaction strongly matches known scam patterns. Do not proceed with payment.": "This UPI transaction strongly matches known scam patterns. Do not proceed with payment.",
        "No common phone scam patterns detected in this call.": "No common phone scam patterns detected in this call.",
        "This call has some characteristics worth double-checking.": "This call has some characteristics worth double-checking.",
        "This call strongly matches known phone scam scripts. Do not act on it.": "This call strongly matches known phone scam scripts. Do not act on it.",
        "No common threat patterns detected in this QR code's content.": "No common threat patterns detected in this QR code's content.",
        "This QR code's content has some characteristics worth double-checking.": "This QR code's content has some characteristics worth double-checking.",
        "This QR code strongly matches known scam patterns. Do not act on it.": "This QR code strongly matches known scam patterns. Do not act on it.",
        # XAI reasons (from message_reasons.py _CATEGORIES explanations)
        "Uses urgency or pressure language to rush you into acting without thinking.": "Uses urgency or pressure language to rush you into acting without thinking.",
        "Claims you've won a prize or lottery — a classic scam hook.": "Claims you've won a prize or lottery — a classic scam hook.",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "Impersonates a bank/service asking you to 'verify' or 'update' account details.",
        "Contains a link — always check the actual domain before clicking.": "Contains a link — always check the actual domain before clicking.",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "Threatens a legal or account-loss consequence to intimidate you into responding.",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "Offers something free or too-good-to-be-true in exchange for personal information.",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "The overall wording and structure statistically resembles scam messages the model was trained on.",
        # XAI tips (from message_reasons.py safety_tips)
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "Verify suspicious requests by contacting the organization directly via their official app or number.",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "This message shows no common scam indicators, but always stay cautious with unexpected requests.",
        "Don't click any links or reply with personal details until you've verified the sender.": "Don't click any links or reply with personal details until you've verified the sender.",
        "Search online for the exact wording — scam templates are often reused and reported.": "Search online for the exact wording — scam templates are often reused and reported.",
        "Do not click any links, call any numbers, or reply to this message.": "Do not click any links, call any numbers, or reply to this message.",
        "Block and report the sender through your messaging app.": "Block and report the sender through your messaging app.",
        "If you already shared details, contact your bank immediately to secure your account.": "If you already shared details, contact your bank immediately to secure your account.",
        # XAI speech_text prefixes
        "Warning: This message has been detected as scam.": "Warning: This message has been detected as scam.",
        "Warning: This message has been detected as suspicious.": "Warning: This message has been detected as suspicious.",
        "Do not share personal details or click any links.": "Do not share personal details or click any links.",
    },
}

_CORE_TRANSLATIONS = {
    "hi": {
        "safe": "सुरक्षित", "suspicious": "संदिग्ध", "scam": "धोखाधड़ी",
        "Confidence": "विश्वास स्तर", "Risk Score": "जोखिम स्कोर",
        "Why this verdict?": "यह निष्कर्ष क्यों?", "Recommended Actions": "सुझाई गई कार्रवाइयाँ",
        "Probability": "संभाव्यता", "Safe": "सुरक्षित", "Scam": "धोखाधड़ी",
        "View Full Scan Record": "पूरा स्कैन रिकॉर्ड देखें",
        # XAI reasons
        "Uses urgency or pressure language to rush you into acting without thinking.": "आपको बिना सोचे तुरंत कार्रवाई करने के लिए दबाव डालने वाली भाषा का उपयोग करता है।",
        "Claims you've won a prize or lottery — a classic scam hook.": "दावा करता है कि आपने पुरस्कार या लॉटरी जीती है — यह एक सामान्य धोखाधड़ी की चाल है।",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "OTP/PIN/कार्ड/बैंक जानकारी मांगता है — वैध सेवाएं कभी संदेश द्वारा यह नहीं मांगतीं।",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "बैंक/सेवा का रूप धारण कर खाता विवरण 'सत्यापित' या 'अपडेट' करने के लिए कहता है।",
        "Contains a link — always check the actual domain before clicking.": "एक लिंक है — क्लिक करने से पहले हमेशा वास्तविक डोमेन की जांच करें।",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "कानूनी कार्रवाई या खाता बंद होने की धमकी देकर आपको डराने की कोशिश करता है।",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "व्यक्तिगत जानकारी के बदले में मुफ्त या अविश्वसनीय रूप से अच्छी चीज की पेशकश करता है।",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "आपके नाम के बजाय सामान्य अभिवादन का उपयोग करता है — यह बड़े पैमाने पर भेजे गए धोखाधड़ी संदेशों की पहचान है।",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "संदेश की शब्दावली और संरचना उन धोखाधड़ी संदेशों से मिलती है जिन पर मॉडल को प्रशिक्षित किया गया था।",
        # XAI tips
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "कभी भी किसी को OTP, PIN, CVV या पासवर्ड न दें, भले ही वे आपके बैंक का दावा करें।",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "संदिग्ध अनुरोधों की पुष्टि सीधे संगठन की आधिकारिक ऐप या नंबर से करें।",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "इस संदेश में कोई सामान्य धोखाधड़ी संकेत नहीं है, लेकिन अप्रत्याशित अनुरोधों से सदैव सावधान रहें।",
        "Don't click any links or reply with personal details until you've verified the sender.": "प्रेषक की पुष्टि किए बिना किसी भी लिंक पर क्लिक न करें या व्यक्तिगत विवरण न दें।",
        "Search online for the exact wording — scam templates are often reused and reported.": "सटीक शब्दों को ऑनलाइन खोजें — धोखाधड़ी के टेम्प्लेट अक्सर दोबारा उपयोग किए जाते हैं।",
        "Do not click any links, call any numbers, or reply to this message.": "किसी भी लिंक पर क्लिक न करें, कोई नंबर न डायल करें, और इस संदेश का जवाब न दें।",
        "Block and report the sender through your messaging app.": "अपने मैसेजिंग ऐप से प्रेषक को ब्लॉक और रिपोर्ट करें।",
        "If you already shared details, contact your bank immediately to secure your account.": "यदि आपने विवरण साझा कर दिया है, तो तुरंत अपने बैंक से संपर्क करके खाते को सुरक्षित करें।",
        # XAI speech parts
        "Warning: This message has been detected as scam.": "चेतावनी: इस संदेश को धोखाधड़ी के रूप में पहचाना गया है।",
        "Warning: This message has been detected as suspicious.": "चेतावनी: यह संदेश संदिग्ध पाया गया है।",
        "Do not share personal details or click any links.": "व्यक्तिगत जानकारी साझा न करें और किसी भी लिंक पर क्लिक न करें।",
    },
    "kn": {
        "safe": "ಸುರಕ್ಷಿತ", "suspicious": "ಸಂದೇಹಾಸ್ಪದ", "scam": "ಮೋಸ",
        "Confidence": "ವಿಶ್ವಾಸ ಮಟ್ಟ", "Risk Score": "ಅಪಾಯದ ಅಂಕ",
        "Why this verdict?": "ಈ ತೀರ್ಪು ಏಕೆ?", "Recommended Actions": "ಶಿಫಾರಸು ಮಾಡಿದ ಕ್ರಮಗಳು",
        "Probability": "ಸಂಭಾವ್ಯತೆ", "Safe": "ಸುರಕ್ಷಿತ", "Scam": "ಮೋಸ",
        "View Full Scan Record": "ಸಂಪೂರ್ಣ ಸ್ಕ್ಯಾನ್ ದಾಖಲೆ ನೋಡಿ",
        # XAI reasons
        "Uses urgency or pressure language to rush you into acting without thinking.": "ಯೋಚಿಸದೆ ತ್ವರಿತ ಕ್ರಮ ತೆಗೆದುಕೊಳ್ಳಲು ಒತ್ತಡ ಹೇರುವ ಭಾಷೆ ಬಳಸುತ್ತದೆ.",
        "Claims you've won a prize or lottery — a classic scam hook.": "ನೀವು ಬಹುಮಾನ ಅಥವಾ ಲಾಟರಿ ಗೆದ್ದಿದ್ದೀರಿ ಎಂದು ಹೇಳುತ್ತದೆ — ಇದು ಮೋಸದ ಒಂದು ಸಾಮಾನ್ಯ ತಂತ್ರ.",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "OTP/PIN/ಕಾರ್ಡ್/ಬ್ಯಾಂಕ್ ಮಾಹಿತಿ ಕೇಳುತ್ತದೆ — ಇದನ್ನು ವೈಧ ಸೇವೆಗಳು ಸಂದೇಶದ ಮೂಲಕ ಎಂದಿಗೂ ಕೇಳುವುದಿಲ್ಲ.",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "ಬ್ಯಾಂಕ್/ಸೇವೆಯ ರೂಪ ಧರಿಸಿ ಖಾತೆ ವಿವರ 'ಪರಿಶೀಲಿಸಿ' ಅಥವಾ 'ಅಪ್‌ಡೇಟ್ ಮಾಡಿ' ಎಂದು ಕೇಳುತ್ತದೆ.",
        "Contains a link — always check the actual domain before clicking.": "ಲಿಂಕ್ ಒಳಗೊಂಡಿದೆ — ಕ್ಲಿಕ್ ಮಾಡುವ ಮೊದಲು ನಿಜವಾದ ಡೊಮೈನ್ ಪರಿಶೀಲಿಸಿ.",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "ಕಾನೂನು ಕ್ರಮ ಅಥವಾ ಖಾತೆ ಮುಚ್ಚುವ ಬೆದರಿಕೆ ಒಡ್ಡಿ ಭಯ ಹುಟ್ಟಿಸಲು ಪ್ರಯತ್ನಿಸುತ್ತದೆ.",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಗೆ ಬದಲಾಗಿ ಉಚಿತ ಅಥವಾ ನಂಬಲಾಗದಷ್ಟು ಒಳ್ಳೆಯ ಪ್ರಸ್ತಾಪ ನೀಡುತ್ತದೆ.",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "ನಿಮ್ಮ ಹೆಸರಿನ ಬದಲು ಸಾಮಾನ್ಯ ಶುಭಾಶಯ ಬಳಸುತ್ತದೆ — ಬೃಹತ್ ಮೋಸ ಸಂದೇಶಗಳ ಲಕ್ಷಣ.",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "ಸಂದೇಶದ ಒಟ್ಟಾರೆ ಭಾಷೆ ಮತ್ತು ರಚನೆಯು ಮಾದರಿ ತರಬೇತಿ ಪಡೆದ ಮೋಸ ಸಂದೇಶಗಳನ್ನು ಹೋಲುತ್ತದೆ.",
        # XAI tips
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "OTP, PIN, CVV ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಯಾರಿಗೂ ನೀಡಬೇಡಿ, ಅವರು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಎಂದು ಹೇಳಿದರೂ ಸಹ.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ಸಂಖ್ಯೆ ಮೂಲಕ ನೇರವಾಗಿ ಸಂಸ್ಥೆಯನ್ನು ಸಂಪರ್ಕಿಸಿ ಸಂದೇಹಾಸ್ಪದ ವಿನಂತಿಗಳನ್ನು ಪರಿಶೀಲಿಸಿ.",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "ಈ ಸಂದೇಶದಲ್ಲಿ ಸಾಮಾನ್ಯ ಮೋಸ ಸೂಚನೆಗಳಿಲ್ಲ, ಆದರೆ ಅಚ್ಚರಿಯ ವಿನಂತಿಗಳಿಗೆ ಯಾವಾಗಲೂ ಜಾಗ್ರತೆ ವಹಿಸಿ.",
        "Don't click any links or reply with personal details until you've verified the sender.": "ಕಳುಹಿಸಿದವರನ್ನು ಪರಿಶೀಲಿಸದ ಹೊರತು ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ವೈಯಕ್ತಿಕ ವಿವರ ನೀಡಬೇಡಿ.",
        "Search online for the exact wording — scam templates are often reused and reported.": "ನಿಖರ ಶಬ್ದಗಳನ್ನು ಆನ್‌ಲೈನ್‌ನಲ್ಲಿ ಹುಡುಕಿ — ಮೋಸ ಟೆಂಪ್ಲೇಟ್‌ಗಳನ್ನು ಮತ್ತೆ ಮತ್ತೆ ಬಳಸಲಾಗುತ್ತದೆ.",
        "Do not click any links, call any numbers, or reply to this message.": "ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ, ಯಾವ ಸಂಖ್ಯೆಗೂ ಕರೆ ಮಾಡಬೇಡಿ, ಈ ಸಂದೇಶಕ್ಕೆ ಉತ್ತರಿಸಬೇಡಿ.",
        "Block and report the sender through your messaging app.": "ನಿಮ್ಮ ಮೆಸೇಜಿಂಗ್ ಆ್ಯಪ್ ಮೂಲಕ ಕಳುಹಿಸಿದವರನ್ನು ಬ್ಲಾಕ್ ಮಾಡಿ ಮತ್ತು ವರದಿ ಮಾಡಿ.",
        "If you already shared details, contact your bank immediately to secure your account.": "ನೀವು ಈಗಾಗಲೇ ವಿವರ ಹಂಚಿಕೊಂಡಿದ್ದರೆ, ತಕ್ಷಣ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಅನ್ನು ಸಂಪರ್ಕಿಸಿ ಖಾತೆ ಸುರಕ್ಷಿತಗೊಳಿಸಿ.",
        # XAI speech parts
        "Warning: This message has been detected as scam.": "ಎಚ್ಚರಿಕೆ: ಈ ಸಂದೇಶವನ್ನು ಮೋಸ ಎಂದು ಗುರುತಿಸಲಾಗಿದೆ.",
        "Warning: This message has been detected as suspicious.": "ಎಚ್ಚರಿಕೆ: ಈ ಸಂದೇಶ ಸಂದೇಹಾಸ್ಪದ ಎಂದು ಕಂಡುಬಂದಿದೆ.",
        "Do not share personal details or click any links.": "ವೈಯಕ್ತಿಕ ವಿವರ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ ಮತ್ತು ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.",
    },
    "te": {
        "safe": "సురక్షితం", "suspicious": "అనుమానాస్పదం", "scam": "మోసం",
        "Confidence": "నమ్మక స్థాయి", "Risk Score": "ప్రమాద స్కోర్",
        "Why this verdict?": "ఈ తీర్పు ఎందుకు?", "Recommended Actions": "సూచించిన చర్యలు",
        "Probability": "సంభావ్యత", "Safe": "సురక్షితం", "Scam": "మోసం",
        "View Full Scan Record": "పూర్తి స్కాన్ రికార్డును చూడండి",
        # XAI reasons
        "Uses urgency or pressure language to rush you into acting without thinking.": "ఆలోచించకుండా వెంటనే చర్య తీసుకునేలా ఒత్తిడి చేసే భాషను ఉపయోగిస్తుంది.",
        "Claims you've won a prize or lottery — a classic scam hook.": "మీరు బహుమతి లేదా లాటరీ గెలిచారని చెప్తుంది — ఇది సాధారణ మోసం పద్ధతి.",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "OTP/PIN/కార్డ్/బ్యాంక్ వివరాలు అడుగుతుంది — చట్టబద్ధ సేవలు ఎప్పుడూ మెసేజ్ ద్వారా ఇవి అడగవు.",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "బ్యాంక్/సేవగా నటించి ఖాతా వివరాలు 'ధృవీకరించండి' లేదా 'నవీకరించండి' అని కోరుతుంది.",
        "Contains a link — always check the actual domain before clicking.": "లింక్ ఉంది — క్లిక్ చేయడానికి ముందు నిజమైన డొమైన్ తనిఖీ చేయండి.",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "చట్టపరమైన చర్య లేదా ఖాతా మూసివేత భయపెట్టడానికి బెదిరిస్తుంది.",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "వ్యక్తిగత సమాచారానికి బదులు ఉచిత లేదా నమ్మలేని అందమైన ఆఫర్ ఇస్తుంది.",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "మీ పేరుకు బదులు సాధారణ పలకరింపు వాడుతుంది — ఇది పెద్ద ఎత్తున పంపిన మోసపు సందేశాల లక్షణం.",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "సందేశపు మొత్తం పదజాలం మరియు నిర్మాణం మోడల్ శిక్షణ పొందిన మోసపు సందేశాలను పోలి ఉంది.",
        # XAI tips
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "OTP, PIN, CVV లేదా పాస్‌వర్డ్‌లను ఎవరికీ చెప్పవద్దు, వారు మీ బ్యాంక్ అని చెప్పినా సరే.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "అనుమానాస్పద అభ్యర్థనలను అధికారిక యాప్ లేదా నంబర్ ద్వారా నేరుగా సంస్థను సంప్రదించి ధృవీకరించండి.",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "ఈ సందేశంలో సాధారణ మోసం సూచనలు లేవు, అయినా అనూహ్య అభ్యర్థనలతో జాగ్రత్తగా ఉండండి.",
        "Don't click any links or reply with personal details until you've verified the sender.": "పంపినవారిని ధృవీకరించే వరకు ఏ లింక్‌నూ క్లిక్ చేయవద్దు లేదా వ్యక్తిగత వివరాలు ఇవ్వవద్దు.",
        "Search online for the exact wording — scam templates are often reused and reported.": "ఖచ్చితమైన పదాలను ఆన్‌లైన్‌లో వెతకండి — మోసం టెంప్లేట్‌లు తరచుగా మళ్లీ ఉపయోగించబడతాయి.",
        "Do not click any links, call any numbers, or reply to this message.": "ఏ లింక్‌నూ క్లిక్ చేయవద్దు, ఏ నంబర్‌కూ కాల్ చేయవద్దు, ఈ సందేశానికి జవాబు ఇవ్వవద్దు.",
        "Block and report the sender through your messaging app.": "మీ మెసేజింగ్ యాప్ ద్వారా పంపినవారిని బ్లాక్ చేసి రిపోర్ట్ చేయండి.",
        "If you already shared details, contact your bank immediately to secure your account.": "వివరాలు ఇచ్చేసి ఉంటే, వెంటనే మీ బ్యాంక్‌ను సంప్రదించి ఖాతాను సురక్షితం చేయండి.",
        # XAI speech parts
        "Warning: This message has been detected as scam.": "హెచ్చరిక: ఈ సందేశం మోసంగా గుర్తించబడింది.",
        "Warning: This message has been detected as suspicious.": "హెచ్చరిక: ఈ సందేశం అనుమానాస్పదంగా కనిపించింది.",
        "Do not share personal details or click any links.": "వ్యక్తిగత వివరాలు చెప్పవద్దు లేదా ఏ లింక్‌నూ క్లిక్ చేయవద్దు.",
    },
    "ta": {
        "safe": "பாதுகாப்பானது", "suspicious": "சந்தேகத்திற்குரியது", "scam": "மோசடி",
        "Confidence": "நம்பகத்தன்மை", "Risk Score": "ஆபத்து மதிப்பெண்",
        "Why this verdict?": "இந்த முடிவு ஏன்?", "Recommended Actions": "பரிந்துரைக்கப்பட்ட நடவடிக்கைகள்",
        "Probability": "சாத்தியம்", "Safe": "பாதுகாப்பானது", "Scam": "மோசடி",
        "View Full Scan Record": "முழு ஸ்கேன் பதிவைக் காண்க",
        # XAI reasons
        "Uses urgency or pressure language to rush you into acting without thinking.": "யோசிக்காமல் உடனே செயல்படுத்த அவசரப்படுத்தும் மொழியை பயன்படுத்துகிறது.",
        "Claims you've won a prize or lottery — a classic scam hook.": "நீங்கள் பரிசு அல்லது லாட்டரி வென்றதாக கூறுகிறது — இது ஒரு பழைய மோசடி தந்திரம்.",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "OTP/PIN/கார்டு/வங்கி தகவல் கேட்கிறது — சட்டப்பூர்வ சேவைகள் இதை செய்திகளில் கேட்பதில்லை.",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "வங்கி/சேவையாக நடித்து கணக்கு விவரங்களை 'சரிபார்க்க' அல்லது 'புதுப்பிக்க' கேட்கிறது.",
        "Contains a link — always check the actual domain before clicking.": "ஒரு இணைப்பு உள்ளது — கிளிக் செய்வதற்கு முன் உண்மையான டொமைனை சரிபார்க்கவும்.",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "சட்ட நடவடிக்கை அல்லது கணக்கு இழப்பு பயமுறுத்தலை பயன்படுத்துகிறது.",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "தனிப்பட்ட தகவலுக்கு ஈடாக இலவசமான அல்லது நம்பமுடியாத சலுகை தருகிறது.",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "உங்கள் பெயருக்கு பதிலாக பொதுவான வாழ்த்தை பயன்படுத்துகிறது — பாரிய மோசடி செய்திகளின் அடையாளம்.",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "செய்தியின் மொத்த வார்த்தைகளும் அமைப்பும் மாதிரி பயிற்சி பெற்ற மோசடி செய்திகளை ஒத்திருக்கின்றன.",
        # XAI tips
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "உங்கள் வங்கி என்று சொன்னாலும் யாரிடமும் OTP, PIN, CVV அல்லது கடவுச்சொல் சொல்லாதீர்கள்.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "அலுவலக ஆப் அல்லது எண்ணில் நேரடியாக தொடர்பு கொண்டு சந்தேகத்தை உறுதிப்படுத்தவும்.",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "இந்த செய்தியில் பொதுவான மோசடி அறிகுறிகள் இல்லை, ஆனால் எப்போதும் எதிர்பாராத கோரிக்கைகளில் எச்சரிக்கையாக இருங்கள்.",
        "Don't click any links or reply with personal details until you've verified the sender.": "அனுப்பியவரை சரிபார்க்காமல் எந்த இணைப்பையும் கிளிக் செய்யாதீர்கள் அல்லது தனிப்பட்ட தகவல் தராதீர்கள்.",
        "Search online for the exact wording — scam templates are often reused and reported.": "சரியான வார்த்தைகளை ஆன்லைனில் தேடுங்கள் — மோசடி டெம்பிளேட்கள் அடிக்கடி மீண்டும் பயன்படுத்தப்படுகின்றன.",
        "Do not click any links, call any numbers, or reply to this message.": "எந்த இணைப்பையும் கிளிக் செய்யாதீர்கள், எந்த எண்ணையும் அழைக்காதீர்கள், இந்த செய்திக்கு பதில் சொல்லாதீர்கள்.",
        "Block and report the sender through your messaging app.": "உங்கள் மெசேஜிங் ஆப் மூலம் அனுப்பியவரை தடு செய்து புகாரளிக்கவும்.",
        "If you already shared details, contact your bank immediately to secure your account.": "விவரங்கள் கொடுத்திருந்தால், உடனடியாக உங்கள் வங்கியை தொடர்பு கொண்டு கணக்கை பாதுகாக்கவும்.",
        # XAI speech parts
        "Warning: This message has been detected as scam.": "எச்சரிக்கை: இந்த செய்தி மோசடி என கண்டறியப்பட்டது.",
        "Warning: This message has been detected as suspicious.": "எச்சரிக்கை: இந்த செய்தி சந்தேகத்திற்குரியது என கண்டறியப்பட்டது.",
        "Do not share personal details or click any links.": "தனிப்பட்ட தகவல்களை பகிர்ந்துகொள்ளாதீர்கள் அல்லது இணைப்புகளை கிளிக் செய்யாதீர்கள்.",
    },
    "ml": {
        "safe": "സുരക്ഷിതം", "suspicious": "സംശയാസ്പദം", "scam": "തട്ടിപ്പ്",
        "Confidence": "വിശ്വാസ്യത", "Risk Score": "അപകട സ്കോർ",
        "Why this verdict?": "ഈ വിധി എന്തുകൊണ്ട്?", "Recommended Actions": "ശുപാർശ ചെയ്യുന്ന നടപടികൾ",
        "Probability": "സാധ്യത", "Safe": "സുരക്ഷിതം", "Scam": "തട്ടിപ്പ്",
        "View Full Scan Record": "പൂർണ്ണ സ്കാൻ രേഖ കാണുക",
        # XAI reasons
        "Uses urgency or pressure language to rush you into acting without thinking.": "ആലോചിക്കാതെ ഉടൻ പ്രവർത്തിക്കാൻ നിർബന്ധിക്കുന്ന ഭാഷ ഉപയോഗിക്കുന്നു.",
        "Claims you've won a prize or lottery — a classic scam hook.": "നിങ്ങൾ ഒരു സമ്മാനം അല്ലെങ്കിൽ ലോട്ടറി നേടിയെന്ന് അവകാശപ്പെടുന്നു — ഇതൊരു സാധാരണ തട്ടിപ്പ് തന്ത്രം.",
        "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message.": "OTP/PIN/കാർഡ്/ബാങ്ക് വിവരങ്ങൾ ആവശ്യപ്പെടുന്നു — നിയമാനുസൃത സേവനങ്ങൾ ഇത് സന്ദേശത്തിലൂടെ ചോദിക്കില്ല.",
        "Impersonates a bank/service asking you to 'verify' or 'update' account details.": "ബാങ്ക്/സേവനമായി നടിച്ച് അക്കൗണ്ട് വിവരങ്ങൾ 'സ്ഥിരീകരിക്കാൻ' അല്ലെങ്കിൽ 'അപ്‌ഡേറ്റ് ചെയ്യാൻ' ആവശ്യപ്പെടുന്നു.",
        "Contains a link — always check the actual domain before clicking.": "ഒരു ലിങ്ക് ഉണ്ട് — ക്ലിക്ക് ചെയ്യുന്നതിന് മുൻപ് ഡൊമൈൻ പരിശോധിക്കുക.",
        "Threatens a legal or account-loss consequence to intimidate you into responding.": "നിയമ നടപടി അല്ലെങ്കിൽ അക്കൗണ്ട് നഷ്ടം ഭീഷണി ഉപയോഗിക്കുന്നു.",
        "Offers something free or too-good-to-be-true in exchange for personal information.": "വ്യക്തിഗത വിവരങ്ങൾക്ക് പകരം സൗജന്യമോ അവിശ്വസനീയമോ ആയ ഓഫർ നൽകുന്നു.",
        "Uses a generic greeting instead of your name, typical of mass-sent scam blasts.": "നിങ്ങളുടെ പേരിന് പകരം സാധാരണ അഭിവാദ്യം ഉപയോഗിക്കുന്നു — ഇത് കൂട്ടമായി അയക്കുന്ന തട്ടിപ്പ് സന്ദേശങ്ങളുടെ സവിശേഷത.",
        "The overall wording and structure statistically resembles scam messages the model was trained on.": "സന്ദേശത്തിന്റെ ആകെ ഭാഷയും ഘടനയും മോഡൽ പരിശീലനം ലഭിച്ച തട്ടിപ്പ് സന്ദേശങ്ങളോട് സാദൃശ്യം കാണിക്കുന്നു.",
        # XAI tips
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.": "ഒരിക്കലും OTP, PIN, CVV അല്ലെങ്കിൽ പാസ്‌വേഡ് ആർക്കും നൽകരുത്, അവർ നിങ്ങളുടെ ബാങ്ക് ആണെന്ന് അവകാശപ്പെട്ടാലും.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.": "ഔദ്യോഗിക ആപ്പ് അല്ലെങ്കിൽ നമ്പർ വഴി നേരിട്ട് ബന്ധപ്പെട്ട് സംശയകരമായ അഭ്യർത്ഥനകൾ സ്ഥിരീകരിക്കുക.",
        "This message shows no common scam indicators, but always stay cautious with unexpected requests.": "ഈ സന്ദേശത്തിൽ സാധാരണ തട്ടിപ്പ് സൂചനകളൊന്നുമില്ല, എന്നാലും അപ്രതീക്ഷിത അഭ്യർത്ഥനകളിൽ ജാഗ്രത പാലിക്കുക.",
        "Don't click any links or reply with personal details until you've verified the sender.": "അയച്ചയാളെ സ്ഥിരീകരിക്കാതെ ഒരു ലിങ്കിലും ക്ലിക്ക് ചെയ്യരുത് അല്ലെങ്കിൽ വ്യക്തിഗത വിവരങ്ങൾ നൽകരുത്.",
        "Search online for the exact wording — scam templates are often reused and reported.": "കൃത്യമായ വാക്കുകൾ ഓൺലൈനിൽ തിരയുക — തട്ടിപ്പ് ടെംപ്ലേറ്റുകൾ പലപ്പോഴും ആവർത്തിക്കും.",
        "Do not click any links, call any numbers, or reply to this message.": "ഒരു ലിങ്കിലും ക്ലിക്ക് ചെയ്യരുത്, ഒരു നമ്പറിലും വിളിക്കരുത്, ഈ സന്ദേശത്തിന് മറുപടി നൽകരുത്.",
        "Block and report the sender through your messaging app.": "നിങ്ങളുടെ മെസേജിങ് ആപ്പ് വഴി അയച്ചയാളെ ബ്ലോക്ക് ചെയ്ത് റിപ്പോർട്ട് ചെയ്യുക.",
        "If you already shared details, contact your bank immediately to secure your account.": "വിവരങ്ങൾ പങ്കുവച്ചിട്ടുണ്ടെങ്കിൽ, ഉടൻ ബാങ്കുമായി ബന്ധപ്പെട്ട് അക്കൗണ്ട് സുരക്ഷിതമാക്കുക.",
        # XAI speech parts
        "Warning: This message has been detected as scam.": "മുന്നറിയിപ്പ്: ഈ സന്ദേശം തട്ടിപ്പ് ആണെന്ന് കണ്ടെത്തിയിട്ടുണ്ട്.",
        "Warning: This message has been detected as suspicious.": "മുന്നറിയിപ്പ്: ഈ സന്ദേശം സംശയാസ്പദമായി കണ്ടെത്തിയിരിക്കുന്നു.",
        "Do not share personal details or click any links.": "വ്യക്തിഗത വിവരങ്ങൾ പങ്കുവയ്ക്കരുത് അല്ലെങ്കിൽ ഒരു ലിങ്കിലും ക്ലിക്ക് ചെയ്യരുത്.",
    },
}

for _language, _values in _CORE_TRANSLATIONS.items():
    _TRANSLATIONS[_language] = {**_TRANSLATIONS["en"], **_values}


def normalize_language(language):
    return language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def detect_supported_language(text, preferred_language=DEFAULT_LANGUAGE):
    """Detect one of the supported scripts, falling back to the UI choice."""
    script_ranges = {
        "hi": (0x0900, 0x097F),
        "kn": (0x0C80, 0x0CFF),
        "te": (0x0C00, 0x0C7F),
        "ta": (0x0B80, 0x0BFF),
        "ml": (0x0D00, 0x0D7F),
    }
    counts = {
        language: sum(start <= ord(character) <= end for character in str(text or ""))
        for language, (start, end) in script_ranges.items()
    }
    detected, count = max(counts.items(), key=lambda item: item[1])
    return detected if count else normalize_language(preferred_language)


@lru_cache(maxsize=512)
def translate_text(text, source_language="auto", target_language=DEFAULT_LANGUAGE):
    """Translate user text for the English-only detector and localized alerts.

    Translation is deliberately outside the classifier. If the optional online
    translator is unavailable, the original text is returned so scans still
    fail gracefully instead of changing prediction behavior.
    """
    if not text or normalize_language(target_language) == source_language:
        return text
    target_language = normalize_language(target_language)
    providers = []
    try:
        from deep_translator import GoogleTranslator, MyMemoryTranslator

        source = source_language if source_language == "auto" else TRANSLATOR_LANGUAGE_CODES.get(source_language, "auto")
        target = TRANSLATOR_LANGUAGE_CODES[target_language]
        providers.append(GoogleTranslator(source=source, target=target))
        # MyMemory supports Indian language regional codes and is a useful
        # fallback when Google's public endpoint rate-limits the application.
        if source_language != "auto":
            providers.append(MyMemoryTranslator(
                source=_MYMEMORY_LANGUAGE_CODES.get(source_language, source_language),
                target=_MYMEMORY_LANGUAGE_CODES[target_language],
            ))
    except Exception as error:  # noqa: BLE001 - optional dependency
        logger.warning("Translation providers unavailable: %s", error)
        return text

    for provider in providers:
        try:
            translated = provider.translate(str(text))
            if translated:
                return translated
        except Exception as error:  # noqa: BLE001 - try the next provider
            logger.warning("Translation provider failed: %s", error)
    return text


def to_english(text, source_language="auto"):
    source_language = detect_supported_language(text, source_language)
    return translate_text(text, source_language, "en")


def from_english(text, target_language=DEFAULT_LANGUAGE):
    return translate_text(text, "en", target_language)


def translate(value, language=DEFAULT_LANGUAGE):
    """Translate a catalogued string, with safe English fallback."""
    if value is None:
        return value
    language = normalize_language(language)
    text = str(value)
    translated = _TRANSLATIONS[language].get(text)
    if translated is not None:
        return translated

    # Module-specific warnings share the same three safety meanings. This
    # keeps every scan surface translated without duplicating near-identical
    # catalog entries for message, URL, UPI, QR, screenshot, and voice.
    generic_status = {
        "safe": {
            "hi": "कोई सामान्य खतरे के संकेत नहीं मिले। फिर भी सावधानी बरतें।",
            "kn": "ಸಾಮಾನ್ಯ ಅಪಾಯದ ಸೂಚನೆಗಳು ಕಂಡುಬಂದಿಲ್ಲ. ಆದರೂ ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ.",
            "te": "సాధారణ ప్రమాద సూచనలు కనిపించలేదు. అయినా జాగ్రత్తగా ఉండండి.",
            "ta": "பொதுவான ஆபத்து அறிகுறிகள் இல்லை. இருப்பினும் எச்சரிக்கையாக இருங்கள்.",
            "ml": "സാധാരണ അപകട സൂചനകൾ കണ്ടെത്തിയില്ല. എന്നിരുന്നാലും ജാഗ്രത പാലിക്കുക.",
        },
        "suspicious": {
            "hi": "इस परिणाम में कुछ संदिग्ध विशेषताएँ हैं। स्वतंत्र रूप से जाँच करें।",
            "kn": "ಈ ಫಲಿತಾಂಶದಲ್ಲಿ ಕೆಲವು ಅನುಮಾನಾಸ್ಪದ ಲಕ್ಷಣಗಳಿವೆ. ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ.",
            "te": "ఈ ఫలితంలో కొన్ని అనుమానాస్పద లక్షణాలు ఉన్నాయి. స్వతంత్రంగా తనిఖీ చేయండి.",
            "ta": "இந்த முடிவில் சில சந்தேகமான அம்சங்கள் உள்ளன. தனியாகச் சரிபார்க்கவும்.",
            "ml": "ഈ ഫലത്തിൽ ചില സംശയാസ്പദ സവിശേഷതകളുണ്ട്. സ്വതന്ത്രമായി പരിശോധിക്കുക.",
        },
        "scam": {
            "hi": "यह परिणाम ज्ञात धोखाधड़ी पैटर्न से बहुत मिलता है। आगे कार्रवाई न करें।",
            "kn": "ಈ ಫಲಿತಾಂಶವು ತಿಳಿದಿರುವ ಮೋಸ ಮಾದರಿಗಳಿಗೆ ಹೆಚ್ಚು ಹೋಲುತ್ತದೆ. ಮುಂದುವರಿಯಬೇಡಿ.",
            "te": "ఈ ఫలితం తెలిసిన మోస నమూనాలను బలంగా పోలి ఉంది. ముందుకు వెళ్లవద్దు.",
            "ta": "இந்த முடிவு அறியப்பட்ட மோசடி அமைப்புகளை வலுவாக ஒத்திருக்கிறது. தொடர வேண்டாம்.",
            "ml": "ഈ ഫലം അറിയപ്പെടുന്ന തട്ടിപ്പ് രീതികളുമായി വളരെ സാമ്യമുണ്ട്. തുടരരുത്.",
        },
    }
    if language != "en":
        if text.startswith("No common ") or text.startswith("Extracted details are consistent"):
            return generic_status["safe"].get(language, text)
        if "worth double-checking" in text or text.startswith("Some details are missing"):
            return generic_status["suspicious"].get(language, text)
        if "strongly matches" in text or text.startswith("Multiple red flags"):
            return generic_status["scam"].get(language, text)

    match = re.match(r"The AI model is ([\d.]+)% confident that (.+)\.", text)
    if match:
        confidence, phrase = match.groups()
        phrases = {
            "the language pattern strongly matches known scam messages": {
                "hi": "भाषा का पैटर्न ज्ञात धोखाधड़ी संदेशों से बहुत मिलता है", "kn": "ಭಾಷೆಯ ಮಾದರಿಯು ತಿಳಿದಿರುವ ಮೋಸ ಸಂದೇಶಗಳಿಗೆ ಹೆಚ್ಚು ಹೋಲುತ್ತದೆ", "te": "భాషా నమూనా తెలిసిన మోస సందేశాలను బలంగా పోలి ఉంది", "ta": "மொழி அமைப்பு அறியப்பட்ட மோசடி செய்திகளை வலுவாக ஒத்திருக்கிறது", "ml": "ഭാഷാ രീതി അറിയപ്പെടുന്ന തട്ടിപ്പ് സന്ദേശങ്ങളുമായി വളരെ സാമ്യമുണ്ട്",
            },
            "the language does not match common scam patterns": {
                "hi": "भाषा सामान्य धोखाधड़ी पैटर्न से मेल नहीं खाती", "kn": "ಭಾಷೆಯು ಸಾಮಾನ್ಯ ಮೋಸ ಮಾದರಿಗಳಿಗೆ ಹೊಂದಿಕೆಯಾಗುವುದಿಲ್ಲ", "te": "భాష సాధారణ మోస నమూనాలను పోలి లేదు", "ta": "மொழி பொதுவான மோசடி அமைப்புகளுடன் பொருந்தவில்லை", "ml": "ഭാഷ സാധാരണ തട്ടിപ്പ് രീതികളുമായി പൊരുത്തപ്പെടുന്നില്ല",
            },
        }
        phrase_translation = phrases.get(phrase, {}).get(language)
        if phrase_translation:
            return f"{confidence}% {phrase_translation}."
    if language != "en":
        return from_english(text, language)
    return text


def localize_result(result, language=DEFAULT_LANGUAGE):
    """Return a display copy; never mutate model output or persisted data."""
    if not result:
        return result
    localized = dict(result)
    if localized.get("verdict"):
        localized["verdict_label"] = translate(localized["verdict"], language)
    for field in ("error", "warning"):
        if localized.get(field):
            localized[field] = translate(localized[field], language)
    for field in ("reasons", "tips", "recommendations"):
        if localized.get(field):
            localized[field] = [translate(item, language) for item in localized[field]]
    return localized