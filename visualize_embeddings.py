import pickle
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

# Load embeddings directly from face_db.pkl
with open('db/face_db.pkl', 'rb') as f:
    face_db = pickle.load(f)

labels = list(face_db.keys())
embeddings = np.array([face_db[name] for name in labels])

# Reduce 512 dimensions down to 2D using PCA
pca = PCA(n_components=2)
reduced = pca.fit_transform(embeddings)

# Plot
plt.figure(figsize=(8, 6))
colors = plt.cm.tab10(np.linspace(0, 1, len(labels)))

for i, (label, color) in enumerate(zip(labels, colors)):
    plt.scatter(reduced[i, 0], reduced[i, 1], label=label, color=color, s=150)
    plt.annotate(label, (reduced[i, 0], reduced[i, 1]), textcoords="offset points", xytext=(8,8))

plt.title("PCA Visualization of ArcFace Embeddings (512-D → 2D)")
plt.xlabel("Principal Component 1")
plt.ylabel("Principal Component 2")
plt.legend()
plt.tight_layout()
plt.savefig('ArcFace_Embedding_Visualization.png', dpi=300)
plt.show()