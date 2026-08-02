import os
import subprocess
import json
import re
import shlex
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Path to the DPI engine directory
DPI_DIR = "c:/Users/Asus/Desktop/deep packet inspection"
BASH_EXE = r"C:\msys64\usr\bin\bash.exe"

def parse_dpi_output(output):
    result = {
        "summary": {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "forwarded": 0,
            "dropped": 0
        },
        "thread_stats": {},
        "apps": [],
        "domains": []
    }
    
    # Extract Summary
    summary_matches = {
        "total_packets": re.search(r"Total Packets:\s+(\d+)", output),
        "total_bytes": re.search(r"Total Bytes:\s+(\d+)", output),
        "tcp_packets": re.search(r"TCP Packets:\s+(\d+)", output),
        "udp_packets": re.search(r"UDP Packets:\s+(\d+)", output),
        "forwarded": re.search(r"Forwarded:\s+(\d+)", output),
        "dropped": re.search(r"Dropped:\s+(\d+)", output),
    }
    
    for key, match in summary_matches.items():
        if match:
            result["summary"][key] = int(match.group(1))

    # Extract Thread Statistics
    thread_section = re.search(r"THREAD STATISTICS(.*?)[╠╚]", output, re.DOTALL)
    if thread_section:
        thread_lines = thread_section.group(1).strip().split('\n')
        for line in thread_lines:
            match = re.search(r"(LB\d+|FP\d+)\s+(?:dispatched|processed):\s+(\d+)", line)
            if match:
                name, count = match.groups()
                result["thread_stats"][name] = int(count)

    # Extract Application Breakdown
    app_section = re.search(r"APPLICATION BREAKDOWN(.*?)[╠╚]", output, re.DOTALL)
    if app_section:
        app_lines = app_section.group(1).strip().split('\n')
        for line in app_lines:
            # Match: "HTTPS                39  50.6% ##########            ║"
            match = re.search(r"║\s+([A-Za-z0-9/.\-]+)\s+(\d+)\s+([\d.]+)%", line)
            if match:
                app_name, count, percent = match.groups()
                result["apps"].append({
                    "name": app_name.strip(),
                    "count": int(count),
                    "percent": float(percent)
                })

    # Extract Domains
    domain_section = re.search(r"\[Detected Domains/SNIs\](.*?)Output written", output, re.DOTALL)
    if domain_section:
        domain_lines = domain_section.group(1).strip().split('\n')
        for line in domain_lines:
            match = re.search(r"-\s+(.*?)\s+->\s+(.*)", line)
            if match:
                domain, app = match.groups()
                result["domains"].append({
                    "domain": domain.strip(),
                    "app": app.strip()
                })

    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/files', methods=['GET'])
def list_files():
    # List .pcap files in root and uploads folder
    files = []
    
    # Check root for test_dpi.pcap
    root_files = [f for f in os.listdir(DPI_DIR) if f.endswith('.pcap')]
    for f in root_files:
        files.append({"name": f, "path": f})
        
    # Check uploads folder
    if os.path.exists(UPLOAD_FOLDER):
        upload_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.pcap')]
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
        input_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(os.path.join(DPI_DIR, input_path))
        input_file = input_path
        
    if not input_file:
        return jsonify({"error": "No input file provided"}), 400
        
    # Prepare output filename
    base_name = os.path.basename(input_file)
    output_file = os.path.join(OUTPUT_FOLDER, f"out_{base_name}").replace('\\', '/')
    
    # Build command arguments
    args = []
    if block_app:
        args.extend(["--block-app", shlex.quote(block_app)])
    if block_ip:
        args.extend(["--block-ip", shlex.quote(block_ip)])
        
    args_str = " ".join(args)
    
    # Prepare bash command
    # Path conversions for msys64
    bash_cmd = f"export PATH=/mingw64/bin:$PATH && cd '/c/Users/Asus/Desktop/deep packet inspection' && ./dpi_engine.exe {input_file} {output_file} {args_str}"
    
    cmd = [
        BASH_EXE,
        "-lc",
        bash_cmd
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=DPI_DIR
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            return jsonify({
                "error": "DPI engine failed",
                "stderr": stderr,
                "stdout": stdout
            }), 500
            
        parsed_data = parse_dpi_output(stdout)
        parsed_data['raw_output'] = stdout
        parsed_data['output_file'] = output_file
        
        return jsonify(parsed_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
