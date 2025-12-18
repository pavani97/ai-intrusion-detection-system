# ai-intrusion-detection-system
AI-powered Network Intrusion Detection System using Machine Learning and Real-time Packet Analysis
# AI-Powered Intrusion Detection System

An intelligent network intrusion detection system using machine learning to identify malicious network activities in real-time.

## 🌟 Features

- **Machine Learning Powered**: Uses Random Forest algorithm for high accuracy detection
- **Real-time Monitoring**: Captures and analyzes network packets in real-time
- **NSL-KDD Dataset**: Trained on industry-standard intrusion detection dataset
- **99%+ Accuracy**: Achieves exceptional detection accuracy on test data
- **Extensible Design**: Modular architecture for easy enhancements

## 📊 Performance Metrics

- **Accuracy**: 99.17%
- **Precision**: 
  - Normal traffic: 0.99
  - Attack detection: 1.00
- **Recall**:
  - Normal traffic: 1.00
  - Attack detection: 0.99

## 🛠️ Technologies Used

- Python 3.8+
- Scikit-learn
- Pandas & NumPy
- PyShark for packet capture
- Joblib for model persistence

## 📁 Project Structureai-ids-project/
├── ids_main.py # Main IDS implementation
├── data/
│   ├── KDDTrain+.txt # Training dataset 
│   └── KDDTest+.txt  # Test dataset
└── requirements.txt  # Python dependencies
## 🛠️ Technologies Used

- Python 3.8+
- Scikit-learn
- Pandas & NumPy
- Joblib for model persistence

## 📊 Performance Results

- **Accuracy**: 99.17%
- **Precision**: Normal (0.99), Attack (1.00)
- **Recall**: Normal (1.00), Attack (0.99)

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ai-ids-project.git
   cd ai-ids-project
2. Create a virtual environment:
   ```bash
   python -m venv ids-env
   source ids-env/bin/activate  # On Windows: ids-env\Scripts\activate
3.Install dependencies:   
   ```bash
    pip install -r requirements.txt
4.Download NSL-KDD dataset from Kaggle
  ```bash
     Place KDDTrain+.txt and KDDTest+.txt in the data/ folder

     RUN : python ids_main.py


