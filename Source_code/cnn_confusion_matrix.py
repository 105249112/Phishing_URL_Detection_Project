from sklearn.metrics import ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import numpy as np

cm = np.array([
    [58123, 32],
    [119, 20398]
])

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Benign", "Malicious"]
)

disp.plot(values_format="d")
plt.title("CNN Confusion Matrix")
plt.tight_layout()

plt.savefig("../Models/cnn_confusion_matrix.png", dpi=300)
plt.show()