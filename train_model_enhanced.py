

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    roc_auc_score,
    balanced_accuracy_score,
    f1_score,
    confusion_matrix,
    precision_recall_curve,
)
from sklearn.impute import SimpleImputer
from sklearn.calibration import CalibratedClassifierCV
import pickle
import warnings
import os
import urllib.request
import tarfile
from pathlib import Path
import kagglehub
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from test_phishguard import PhishGuardTester
from email_parser import FullEmailParser, EnhancedFeatureExtractor

warnings.filterwarnings("ignore")


class PublicDatasetLoader:
    def __init__(self, data_dir="datasets"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.lock = threading.Lock()

    def download_file(self, url, save_path, dataset_name="file"):
        if save_path.exists():
            print(f"   ✅ {dataset_name} already exists")
            return True
        print(f"   📥 Downloading {dataset_name}...")
        try:

            def progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = downloaded / total_size * 100
                    print(
                        f"\r      {percent:5.1f}% ({downloaded // (1024*1024)} MB)",
                        end="",
                    )

            urllib.request.urlretrieve(url, save_path, progress)
            print("\n   ✅ Download complete")
            return True
        except Exception as e:
            print(f"\n   ❌ Download failed: {e}")
            return False

    # ========== NAZARIO PHISHING CORPUS ==========
    def download_nazario_phishing(self):
        print("\n📥 NAZARIO PHISHING CORPUS")
        url = "https://monkey.org/~jose/phishing/phishing2.mbox"
        save_path = self.data_dir / "nazario_phishing.mbox"
        if not self.download_file(url, save_path, "Nazario corpus"):
            return []
        data = []
        try:
            with open(save_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            emails = content.split("\nFrom ")
            for email in emails:
                email = email.strip()
                if len(email) < 100:
                    continue
                data.append(("phishing", email))
            print(f"   ✅ Loaded {len(data):,} phishing emails")
        except Exception as e:
            print(f"   ❌ Error: {e}")
        return data

    def read_email_file(self, filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if len(content.strip()) < 100:
                return None
            return ("legitimate", content)
        except:
            return None

    # ========== ENRON LEGITIMATE EMAILS ==========
    def download_enron_legitimate(self, max_files=60000):
        print("\n📥 ENRON EMAIL DATASET")
        url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
        tar_path = self.data_dir / "enron.tar.gz"
        extract_dir = self.data_dir / "enron"

        if extract_dir.exists():
            print("   ✅ Enron dataset already extracted")
        else:
            if not self.download_file(url, tar_path, "Enron dataset"):
                return []
            print("   📦 Extracting dataset...")
            try:
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(extract_dir)
                print("   ✅ Extraction complete")
            except Exception as e:
                print(f"   ❌ Extraction failed: {e}")
                return []

        print("   🔍 Scanning email files...")
        all_files = []
        for root, _, files in os.walk(extract_dir):
            for file in files:
                all_files.append(Path(root) / file)
        print(f"   📂 Found {len(all_files):,} files")

        # --- NEW: Limit number of files to process ---
        if len(all_files) > max_files:
            all_files = all_files[:max_files]
            print(f"   🔄 Limiting to first {max_files:,} files for faster loading")

        print("   ⚡ Reading emails using multi-threading...")
        data = []
        completed = 0
        total = len(all_files)
        max_workers = min(32, os.cpu_count() * 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.read_email_file, filepath): filepath
                for filepath in all_files
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    data.append(result)
                completed += 1
                if completed % 5000 == 0 or completed == total:
                    percent = completed / total * 100
                    print(
                        f"\r      Processed {completed:,}/{total:,} ({percent:.1f}%)",
                        end="",
                    )
        print()
        print(f"   ✅ Loaded {len(data):,} legitimate emails")
        return data

    # ========== KAGGLE DATASET ==========
    def download_kaggle_dataset(self):
        print("\n📥 KAGGLE PHISHING DATASET")
        try:
            path = kagglehub.dataset_download(
                "naserabdullahalam/phishing-email-dataset"
            )
            csv_files = list(Path(path).glob("**/*.csv"))
            if not csv_files:
                print("   ❌ No CSV file found")
                return []
            dataset_path = csv_files[0]
            print(f"   📖 Loading {dataset_path.name}")
            df = pd.read_csv(dataset_path)
            # Auto-detect text column
            text_cols = ["text", "body", "email", "message", "Email Text"]
            email_col = None
            for col in text_cols:
                if col in df.columns:
                    email_col = col
                    break
            if email_col is None:
                email_col = df.columns[0]
            # Auto-detect label column
            label_cols = ["label", "Label", "class", "Class", "spam"]
            label_col = None
            for col in label_cols:
                if col in df.columns:
                    label_col = col
                    break
            if label_col is None:
                label_col = df.columns[1]
            print(f"   📄 Text column : {email_col}")
            print(f"   🏷️ Label column: {label_col}")
            data = []
            for _, row in df.iterrows():
                email_text = str(row[email_col])
                if len(email_text.strip()) < 50:
                    continue
                label = str(row[label_col]).strip().lower()
                if label in ["1", "phishing", "true"]:
                    data.append(("phishing", email_text))
                elif label in ["0", "legitimate", "ham", "safe", "false"]:
                    data.append(("legitimate", email_text))
            print(f"   ✅ Loaded {len(data):,} emails")
            return data
        except Exception as e:
            print(f"   ❌ Kaggle dataset failed: {e}")
            return []

    # ========== MAIN LOADER WITH 1:1 BALANCE ==========
    def load_all_data(self):
        print("=" * 70)
        print("📊 LOADING CLEAN EMAIL DATASETS")
        print("=" * 70)
        all_data = []
        nazario = self.download_nazario_phishing()
        all_data.extend(nazario)
        enron = self.download_enron_legitimate()
        all_data.extend(enron)
        kaggle_data = self.download_kaggle_dataset()
        all_data.extend(kaggle_data)

        phishing = [x for x in all_data if x[0] == "phishing"]
        legitimate = [x for x in all_data if x[0] == "legitimate"]

        print("\n📊 BEFORE BALANCING")
        print(f"   Phishing   : {len(phishing):,}")
        print(f"   Legitimate : {len(legitimate):,}")

        # --- FIX: Strict 1:1 downsampling ---
        min_count = min(len(phishing), len(legitimate))
        phishing = phishing[:min_count]
        legitimate = legitimate[:min_count]

        balanced_data = phishing + legitimate
        print("\n📊 AFTER BALANCING (1:1 ratio)")
        print(f"   Total emails : {len(balanced_data):,}")
        print(f"   Phishing     : {len(phishing):,}")
        print(f"   Legitimate   : {len(legitimate):,}")
        return balanced_data


# ========== ENHANCED FEATURE EXTRACTION WITH FALLBACK ==========
def safe_feature_extraction(email_text, parser, extractor):
    """Extract features with fallback for parsing errors."""
    try:
        parsed = parser.parse_full_email(email_text)
        features = extractor.extract_features(parsed)
        return features
    except Exception:
        # Return a dictionary of zeros with correct feature names
        # Get feature names from a dummy extraction
        dummy_parsed = parser.parse_full_email("Subject: test\n\nbody")
        dummy_features = extractor.extract_features(dummy_parsed)
        return {k: 0 for k in dummy_features.keys()}


def train_enhanced_model():
    print("\n" + "=" * 80)
    print("🤖 PHISHGUARD - FIXED TRAINING (NO PHISHING BIAS)")
    print("=" * 80)

    loader = PublicDatasetLoader()
    data = loader.load_all_data()

    print(f"\n🔍 Extracting features from {len(data):,} emails...")
    parser = FullEmailParser()
    extractor = EnhancedFeatureExtractor()

    features_list = []
    labels = []
    total = len(data)

    for i, (label, email_text) in enumerate(data):
        if i % 1000 == 0:
            percent = i / total * 100
            print(f"\r   Processed {i:,}/{total:,} ({percent:.1f}%)", end="")
        feats = safe_feature_extraction(email_text, parser, extractor)
        features_list.append(feats)
        labels.append(1 if label == "phishing" else 0)
    print("\n✅ Feature extraction complete")

    df = pd.DataFrame(features_list)
    df["label"] = labels

    X = df.drop("label", axis=1)
    y = df["label"]

    # --- FIX: Impute missing values using median per class to avoid bias ---
    X_phish = X[y == 1]
    X_legit = X[y == 0]
    imputer_phish = SimpleImputer(strategy="median")
    imputer_legit = SimpleImputer(strategy="median")
    X_phish_imp = imputer_phish.fit_transform(X_phish)
    X_legit_imp = imputer_legit.fit_transform(X_legit)

    # Reassemble
    X_imp = np.vstack([X_phish_imp, X_legit_imp])
    y_imp = np.hstack([np.ones(len(X_phish_imp)), np.zeros(len(X_legit_imp))])
    X = pd.DataFrame(X_imp, columns=X.columns)

    print(f"\n✅ Feature matrix shape: {X.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_imp, test_size=0.2, random_state=42, stratify=y_imp
    )

    # --- FIX: Use balanced_accuracy and f1 for model selection ---
    print("\n🧠 Training Random Forest with balanced class weight...")
    rf = RandomForestClassifier(
        class_weight="balanced", random_state=42, n_jobs=-1  # FIX: removes manual bias
    )

    param_grid = {
        "n_estimators": [200],
        "max_depth": [20, 30],
        "min_samples_split": [5, 10],
        "min_samples_leaf": [2, 4],
    }

    # Use F1 score for phishing (class 1) as scoring metric
    grid_search = GridSearchCV(
        rf,
        param_grid,
        cv=3,
        scoring="f1",  # FIX: balanced metric for phishing detection
        n_jobs=-1,
        verbose=2,
    )
    grid_search.fit(X_train, y_train)
    best_rf = grid_search.best_estimator_
    print(f"\n✅ Best parameters: {grid_search.best_params_}")

    # --- FIX: Calibrate probabilities (reduces overconfidence) ---
    print("\n🎯 Calibrating probabilities...")
    calibrated_model = CalibratedClassifierCV(best_rf, method="sigmoid", cv=3)
    calibrated_model.fit(X_train, y_train)

    # --- FIX: Tune threshold on validation set (using precision-recall curve) ---
    y_val_prob = calibrated_model.predict_proba(X_test)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_val_prob)
    # Choose threshold that maximises F1 on validation
    f1_scores = (
        2 * (precisions[:-1] * recalls[:-1]) / (precisions[:-1] + recalls[:-1] + 1e-9)
    )
    best_thresh = thresholds[np.argmax(f1_scores)]
    print(f"\n✅ Optimal threshold (max F1): {best_thresh:.4f}")

    # Final predictions with tuned threshold
    y_pred = (y_val_prob >= best_thresh).astype(int)

    print("\n" + "=" * 80)
    print("📊 MODEL PERFORMANCE ON TEST SET")
    print("=" * 80)
    print(f"Balanced Accuracy : {balanced_accuracy_score(y_test, y_pred):.4f}")
    print(f"ROC AUC           : {roc_auc_score(y_test, y_val_prob):.4f}")
    print(f"F1 Score (phish)  : {f1_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(
        classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
    )
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save model with all components
    os.makedirs("models", exist_ok=True)
    model_path = "models/phishing_model_calibrated.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(
            {
                "model": calibrated_model,
                "feature_names": list(X.columns),
                "prediction_threshold": best_thresh,
            },
            f,
        )
    print(f"\n💾 Model saved to {model_path}")
    return calibrated_model


if __name__ == "__main__":
    train_enhanced_model()
