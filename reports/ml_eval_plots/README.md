# 📊 Galeri Visualisasi Evaluasi Model Machine Learning (LightGBM Tier-1)

Buka berkas ini di **VS Code** lalu tekan **`Ctrl + Shift + V`** (atau klik kanan $\rightarrow$ **Markdown: Open Preview**) untuk melihat seluruh visualisasi metrik secara langsung.

---

## 🏆 Master Dashboard (All-in-One Executive View)
![Master Dashboard](./ml_evaluation_master_dashboard.png)

---

## 1. Confusion Matrix
Menunjukkan jumlah dan persentase prediksi benar vs salah (True Positives, True Negatives, False Positives, False Negatives).
![Confusion Matrix](./01_confusion_matrix.png)

---

## 2. Receiver Operating Characteristic (ROC-AUC Curve)
Mengukur kemampuan diskriminasi model membedakan antara ancaman serangan nyata vs background noise operasional (AUC = 0.9968).
![ROC Curve](./02_roc_auc_curve.png)

---

## 3. Precision-Recall Curve (PR-AUC)
Metrik paling krusial untuk dataset SOC yang sangat imbalanced (2.256 Benign vs 270 Threat).
![Precision-Recall Curve](./03_precision_recall_curve.png)

---

## 4. Calibration Curve / Reliability Diagram
Membuktikan kualitas Isotonic Regression: nilai probabilitas keluaran model (0–100%) merefleksikan frekuensi empiris sebenarnya.
![Calibration Curve](./04_calibration_curve.png)

---

## 5. Feature Importance (Bobot Sinyal Perilaku)
Menampilkan fitur dan sinyal telemetri yang paling dominan digunakan model dalam membedakan serangan.
![Feature Importance](./05_feature_importance.png)

---

## 6. Distribusi Probabilitas & Ambang Batas 85% Auto-Close
Menampilkan bagaimana model membagi keputusan ke dalam:
- $\ge 85\%$ Threat: Auto-Close (True Positive)
- $\ge 85\%$ Benign: Auto-Close (Suppression)
- $< 85\%$ (Grey Zone): Diteruskan ke Antrean Tiket Analis SOC
![Confidence Distribution](./06_confidence_distribution_85_threshold.png)

---

## 7. Scorecard Tabel Ringkasan Metrik Kinerja
Tabel metrik resmi model yang siap diekspor ke laporan teknis atau presentasi manajemen.
![Scorecard Table](./07_metrics_summary_table.png)
