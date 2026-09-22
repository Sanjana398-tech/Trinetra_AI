from backend.utils.distilbert_loader import predict_message


message = "Congratulations! You won ₹50,000. Click this link to claim."

result = predict_message(message)

print("\n================================")
print("TRINETRA AI - DISTILBERT TEST")
print("================================")

print("Message:", message)

print("\nPrediction:", result["prediction"])
print("Confidence:", result["confidence"], "%")
print("Safe Probability:", result["safe_probability"], "%")
print("Scam Probability:", result["scam_probability"], "%")