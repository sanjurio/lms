import nltk
import os

nltk_data_path = './nltk_data'
os.makedirs(nltk_data_path, exist_ok=True)

nltk.download('punkt', download_dir=nltk_data_path)
nltk.download('stopwords', download_dir=nltk_data_path)
nltk.download('averaged_perceptron_tagger', download_dir=nltk_data_path)
