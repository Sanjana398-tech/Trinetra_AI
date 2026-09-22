import whisper

from backend.utils.distilbert_loader import predict_message


# ==========================================
# WHISPER MODEL
# ==========================================

print("Loading Whisper base model...")

whisper_model = whisper.load_model("base")

print("✅ Whisper base model loaded!")


# ==========================================
# VOICE SCAM DETECTION
# ==========================================

def analyze_voice(audio_file):

    try:

        # ==========================================
        # STEP 1 - SPEECH TO TEXT
        # ==========================================

        result = whisper_model.transcribe(
            audio_file,
            language="en",
            fp16=False
        )

        text = result["text"].strip()

        if not text:
            return {
                "error": "No speech could be detected from the audio."
            }

        # ==========================================
        # STEP 2 - DISTILBERT SCAM DETECTION
        # ==========================================

        classification = predict_message(text)

        if classification is None:
            return {
                "error": "Message scam detection failed."
            }

        # ==========================================
        # FINAL RESULT
        # ==========================================

        return {
            "transcription": text,
            "prediction": classification["prediction"],
            "confidence": classification["confidence"],
            "safe_probability": classification["safe_probability"],
            "scam_probability": classification["scam_probability"]
        }

    except Exception as e:

        print("❌ Voice scam analysis error:")
        print(e)

        return {
            "error": str(e)
        }