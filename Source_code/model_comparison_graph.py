import matplotlib.pyplot as plt
import numpy as np

models = ["Logistic Regression", "Random Forest", "CNN"]

accuracy = [98.58, 99.00, 99.81]
precision = [99.62, 99.41, 99.84]
recall = [94.92, 96.76, 99.42]
f1 = [97.21, 98.06, 99.63]

x = np.arange(len(models))
width = 0.2

plt.figure(figsize=(10, 6))

plt.bar(x - 1.5 * width, accuracy, width, label="Accuracy")
plt.bar(x - 0.5 * width, precision, width, label="Precision")
plt.bar(x + 0.5 * width, recall, width, label="Recall")
plt.bar(x + 1.5 * width, f1, width, label="F1 Score")

plt.ylabel("Score (%)")
plt.xlabel("Model")
plt.title("Classification Model Performance Comparison")
plt.xticks(x, models)

# Zoom in so differences are visible
plt.ylim(90, 100.5)

plt.legend()
plt.grid(axis="y", alpha=0.3)

plt.tight_layout()
plt.savefig("../Models/model_comparison.png", dpi=300)
plt.show()