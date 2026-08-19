import sys
sys.path.append(".")
from ids.dataset_generator import generate_training_data
from ids.hybrid_ids import HybridIDS
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

print("=== Generating Training Dataset ===")
df = generate_training_data(n_normal=500, n_attack=200)

print("\n=== Training Hybrid IDS ===")
ids = HybridIDS()
y_test, y_pred = ids.train()

print("\n=== Saving Confusion Matrix ===")
disp = ConfusionMatrixDisplay.from_predictions(
    y_test, y_pred,
    display_labels=['Normal', 'Attack'],
    cmap='Blues'
)
plt.title("Hybrid IDS - Confusion Matrix (17 Features)")
plt.tight_layout()
plt.savefig("logs/confusion_matrix.png")
plt.close()
print("Saved to logs/confusion_matrix.png")

print("\n=== Testing All Attack Scenarios ===")
test_cases = [
    {
        'name': 'Normal Login (Work Hours)',
        'features': [
            0, 3, 0.0, 0.92, 0, 0, 300.0, 2, 0, 1,
            50.0, 5000.0, 3.0, 0.0, 0.0, 1.0, 0
        ]
    },
    {
        'name': 'After-Hours Access (5PM-8AM)',
        'features': [
            0, 1, 0.0, 0.85, 0, 0, 500.0, 1, 0, 1,
            40.0, 4000.0, 2.0, 0.0, 0.0, 1.0, 1
        ]
    },
    {
        'name': 'Brute Force Attack',
        'features': [
            10, 0, 1.0, 0.15, 0, 0, 5.0, 20, 2, 0,
            1500.0, 200000.0, 3.0, 2.0, 8.0, 0.3, 0
        ]
    },
    {
        'name': 'Spoof Attack',
        'features': [
            2, 0, 1.0, 0.35, 1, 3, 10.0, 8, 1, 0,
            300.0, 50000.0, 4.0, 1.0, 4.0, 2.5, 0
        ]
    },
    {
        'name': 'Port Scan Attack',
        'features': [
            1, 0, 1.0, 0.20, 0, 0, 5.0, 10, 3, 0,
            3000.0, 80000.0, 200.0, 50.0, 30.0, 7.0, 0
        ]
    },
    {
        'name': 'After-Hours + Brute Force',
        'features': [
            8, 0, 1.0, 0.10, 0, 0, 3.0, 15, 2, 0,
            1200.0, 180000.0, 5.0, 3.0, 7.0, 0.4, 1
        ]
    },
    {
        'name': 'After-Hours + Spoof',
        'features': [
            2, 0, 1.0, 0.30, 1, 2, 8.0, 5, 1, 0,
            200.0, 30000.0, 3.0, 1.0, 3.0, 2.0, 1
        ]
    }
]

for case in test_cases:
    alert, level, reason = ids.predict(case['features'])
    status = "🚨 BLOCKED" if alert else "✅ ALLOWED"
    print(f"\n{case['name']}:")
    print(f"  {status} | Level: {level}")
    print(f"  Reason: {reason}")