# ids_main.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

class AIIntrusionDetectionSystem:
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.feature_columns = None
        
    def load_nsl_kdd_data(self, train_file, test_file=None):
        """
        Load NSL-KDD dataset
        """
        # NSL-KDD column names
        column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
        ]
        
        # Load training data
        print("Loading training data...")
        df_train = pd.read_csv(train_file, names=column_names)
        
        if test_file:
            print("Loading test data...")
            df_test = pd.read_csv(test_file, names=column_names)
            # Combine train and test for better preprocessing
            df = pd.concat([df_train, df_test], ignore_index=True)
        else:
            df = df_train
            
        print(f"Dataset loaded with {len(df)} records")
        return df
    
    def preprocess_data(self, df):
        """
        Preprocess the NSL-KDD data
        """
        print("Preprocessing data...")
        
        # Remove the difficulty_level column (last column)
        df = df.drop('difficulty_level', axis=1)
        
        # Separate features and labels
        X = df.iloc[:, :-1]  # All columns except last (features)
        y = df.iloc[:, -1]   # Last column (labels)
        
        # Store feature columns for later use
        self.feature_columns = X.columns.tolist()
        
        # Handle categorical features
        categorical_columns = ['protocol_type', 'service', 'flag']
        
        for column in categorical_columns:
            if column in X.columns:
                le = LabelEncoder()
                X[column] = le.fit_transform(X[column])
                self.label_encoders[column] = le
        
        # Convert labels to binary (normal vs attack)
        # Normal traffic labeled as 'normal', everything else is an attack
        y = y.apply(lambda x: 0 if x == 'normal' else 1)
        
        return X, y
    
    def train_model(self, X, y):
        """
        Train the AI model
        """
        print("Training model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model Training Complete!")
        print(f"Accuracy: {accuracy * 100:.2f}%")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        return accuracy
    
    def detect_intrusion(self, features):
        """
        Detect if network traffic is normal or malicious
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
            
        # Ensure features are in the right format
        if isinstance(features, list):
            features = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0]
        
        if prediction == 0:
            return "NORMAL", probability[0]
        else:
            return "ATTACK DETECTED", probability[1]
    
    def save_model(self, filename='ids_model.pkl'):
        """
        Save the trained model
        """
        model_data = {
            'model': self.model,
            'label_encoders': self.label_encoders,
            'feature_columns': self.feature_columns
        }
        joblib.dump(model_data, filename)
        print(f"Model saved as {filename}")
    
    def load_model(self, filename='ids_model.pkl'):
        """
        Load a trained model
        """
        model_data = joblib.load(filename)
        self.model = model_data['model']
        self.label_encoders = model_data['label_encoders']
        self.feature_columns = model_data['feature_columns']
        print(f"Model loaded from {filename}")

def main():
    # Initialize the IDS
    ids = AIIntrusionDetectionSystem()
    
    try:
        # Load data (update path to where you saved the files)
        # You'll need to download the NSL-KDD dataset from Kaggle
        # and place KDDTrain+.txt and KDDTest+.txt in the data folder
        df = ids.load_nsl_kdd_data('data/KDDTrain+.txt', 'data/KDDTest+.txt')
        
        # Preprocess data
        X, y = ids.preprocess_data(df)
        
        # Train model
        ids.train_model(X, y)
        
        # Test detection with a sample (using first row of data)
        sample_features = X.iloc[0].values.reshape(1, -1)
        result, confidence = ids.detect_intrusion(sample_features)
        print(f"\nDetection Result: {result} (Confidence: {confidence:.2f})")
        
        # Save model
        ids.save_model()
        
    except FileNotFoundError:
        print("Dataset files not found. Creating sample data for demonstration...")
        
        # Create sample data for demonstration
        sample_data = {
            'duration': [0, 0, 0, 10, 5, 2, 1, 0, 3, 0],
            'protocol_type': [1, 2, 1, 1, 1, 1, 2, 1, 1, 1],  # encoded
            'service': [1, 2, 1, 1, 1, 1, 2, 1, 1, 3],        # encoded
            'flag': [1, 1, 2, 1, 3, 1, 1, 2, 1, 1],           # encoded
            'src_bytes': [200, 100, 5000, 150, 2000, 180, 90, 4500, 120, 300],
            'dst_bytes': [1000, 500, 0, 300, 0, 900, 400, 0, 150, 800],
            'land': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'wrong_fragment': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'urgent': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'hot': [0, 0, 5, 0, 2, 0, 0, 6, 0, 1],
            'num_failed_logins': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'logged_in': [1, 1, 0, 1, 0, 1, 1, 0, 1, 1],
            'num_compromised': [0, 0, 10, 0, 5, 0, 0, 15, 0, 2],
            'root_shell': [0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
            'su_attempted': [0, 0, 1, 0, 0, 0, 0, 1, 0, 0],
            'num_root': [0, 0, 5, 0, 2, 0, 0, 6, 0, 1],
            'label': [0, 0, 1, 0, 1, 0, 0, 1, 0, 0]  # 0=normal, 1=attack
        }
        
        # Create DataFrame
        df_sample = pd.DataFrame(sample_data)
        X_sample = df_sample.drop('label', axis=1)
        y_sample = df_sample['label']
        
        # Train with sample data
        ids.feature_columns = X_sample.columns.tolist()
        ids.train_model(X_sample, y_sample)
        
        # Test with sample
        sample_features = X_sample.iloc[0].values.reshape(1, -1)
        result, confidence = ids.detect_intrusion(sample_features)
        print(f"\nSample Detection Result: {result} (Confidence: {confidence:.2f})")

if __name__ == "__main__":
    main()