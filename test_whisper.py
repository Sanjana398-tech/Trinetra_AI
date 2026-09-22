import whisper

print("================================")
print("TRINETRA AI - WHISPER TEST")
print("================================")

AUDIO_FILE = "voice_tests/Recording.m4a"

print("\nLoading Whisper base model...")

model = whisper.load_model("base")

print("✅ Whisper model loaded!")

print("\nTranscribing audio...")
print("Please wait...")

result = model.transcribe(
    AUDIO_FILE,
    language="en"
)

text = result["text"].strip()

print("\n================================")
print("TRANSCRIPTION RESULT")
print("================================")

print("Text:")
print(text)

print("\n================================")
print("WHISPER TEST COMPLETE")
print("================================")