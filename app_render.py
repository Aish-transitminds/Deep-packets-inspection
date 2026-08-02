import os
import json
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from dpi_python import parse_pcap

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Base directory for finding pcap files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/files', methods=['GET'])
def list_files():
    files = []

    # Check root for .pcap files
    root_files = [f for f in os.listdir(BASE_DIR) if f.endswith('.pcap')]
    for f in root_files:
        files.append({"name": f, "path": f})

    # Check uploads folder
    upload_path = os.path.join(BASE_DIR, UPLOAD_FOLDER)
    if os.path.exists(upload_path):
        upload_files = [f for f in os.listdir(upload_path) if f.endswith('.pcap')]
        for f in upload_files:
            files.append({"name": f, "path": os.path.join(UPLOAD_FOLDER, f).replace('\\', '/')})

    # Deduplicate
    unique_files = list({f['name']: f for f in files}.values())
    return jsonify({"files": unique_files})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    input_file = request.form.get('input_file')
    block_app = request.form.get('block_app')
    block_ip = request.form.get('block_ip')

    # Handle file upload if provided
    if 'file' in request.files and request.files['file'].filename != '':
        file = request.files['file']
        filename = secure_filename(file.filename)
        input_path = os.path.join(BASE_DIR, UPLOAD_FOLDER, filename)
        file.save(input_path)
        input_file = os.path.join(UPLOAD_FOLDER, filename)

    if not input_file:
        return jsonify({"error": "No input file provided"}), 400

    # Resolve full path
    full_path = os.path.join(BASE_DIR, input_file)
    if not os.path.exists(full_path):
        return jsonify({"error": f"File not found: {input_file}"}), 404

    try:
        # Use Python DPI parser
        parsed_data = parse_pcap(
            full_path,
            block_app=block_app if block_app else None,
            block_ip=block_ip if block_ip else None
        )
        parsed_data['output_file'] = f"outputs/out_{os.path.basename(input_file)}"
        return jsonify(parsed_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
