# 🔍 Overview  
This project predicts whether a software vulnerability (CVE) is likely to be exploited in the wild. It compares the performance of centralized deep learning models with federated learning approaches using [Flower](https://flower.dev/).

---

# ❗ Problem  
Most discovered vulnerabilities are never actually exploited. Security teams often waste resources patching low-risk issues while missing high-impact ones. This project aims to prioritize vulnerabilities based on real-world exploitation data to help improve patch management decisions.

---

# 🚀 Features  

- **Dataset**  
  - Over **270,000 CVEs**  
  - **24,590 labeled as exploited** using threat intelligence feeds

- **Text Embeddings**  
  - FastText (trained on CVE descriptions)  
  - TF-IDF  
  - Truncated SVD for dimensionality reduction

- **Tabular Features**  
  - CVSS vectors  
  - Base score, impact score  
  - Confidentiality, integrity, and availability flags

- **Models**  
  - Deep Neural Network (DNN) with custom **Focal Loss** for class imbalance  
  - **Federated Learning simulation** across 5 clients using **Flower**

- **Evaluation Metrics**  
  - Accuracy  
  - Precision  
  - Recall  
  - F1 Score  
  - ROC AUC

---

# ⚙️ How to Use  

1. **Get the Dataset**  
   Download from the following Google Drive links:  
   - [Data (Main)](https://drive.google.com/drive/folders/1Ssggyqo60OFgRfyPZPTiW4zKu3Ds_qOU?usp=drive_link)  
   - [Additional Files](https://drive.google.com/drive/folders/1QEKMcqdIVb39A4tMPyweP8g6-hljj-9q?usp=drive_link)

2. **Install Requirements**  
   ```bash
   pip install tensorflow==2.18.1 numpy==1.26.4 flwr scikit-learn gensim nltk
# my future work
- making a model that can analyis cybersecurity reports and make it readable instead of using LLM model make this function
- make pipline with two model
- improve evalution our model
# 🔐 Federated Learning in Cybersecurity
This project demonstrates how federated learning can be used to improve security analytics while preserving data privacy. It is ideal for scenarios where raw vulnerability data is distributed across multiple organizations and cannot be centrally shared.   
