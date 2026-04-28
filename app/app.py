import os
import sys
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.main import run_agent

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    report = run_agent(filepath)
    return jsonify({'report': report})

if __name__ == '__main__':
    app.run(debug=True)