"""
train_ids.py
-------------
One-command runner to (re)train the Hybrid IDS.

Usage:
    python train_ids.py

Reads:  dataset/ids_training_data.csv   (run generate_ids_dataset.py first
                                          if this doesn't exist yet)
Writes: models/ids_models.pkl           (loaded automatically by main_gui.py
                                          on next startup via HybridIDS.load_models())

Re-run this any time you regenerate or edit the training dataset — it
always overwrites models/ids_models.pkl with a freshly trained model.
"""

import os
import sys

sys.path.append(".")

from ids.hybrid_ids import HybridIDS

DATA_PATH = "dataset/ids_training_data.csv"


def main():
    if not os.path.exists(DATA_PATH):
        print(f"[ERROR] Training data not found at '{DATA_PATH}'.")
        print("Run 'python generate_ids_dataset.py' first to create it.")
        sys.exit(1)

    print(f"Training Hybrid IDS on '{DATA_PATH}'...\n")
    ids = HybridIDS()
    ids.train(data_path=DATA_PATH)

    print(f"\nDone. Models saved to '{ids.model_path}'.")
    print("Restart main_gui.py to pick up the newly trained models.")


if __name__ == "__main__":
    main()