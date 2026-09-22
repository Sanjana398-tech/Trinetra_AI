from backend.utils.voice_scam import analyze_voice


print("================================")
print("TRINETRA AI - VOICE SCAM TEST")
print("================================")

AUDIO_FILE = "voice_tests/Recording.m4a"

print("\nAnalyzing voice...")
print("Please wait...")

result = analyze_voice(AUDIO_FILE)

print("\n================================")
print("VOICE SCAM RESULT")
print("================================")

print(result)

print("\n================================")
print("VOICE SCAM TEST COMPLETE")
print("================================")