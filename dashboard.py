import subprocess
import config
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO
from typing import Dict, Any

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Shared state
blocked_ips = set()
auto_block_enabled = False 

INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IDS/IPS DASHBOARD</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #eee; margin: 0; }
        header { background: #333; padding: 1rem; border-bottom: 3px solid #4CAF50; display: flex; justify-content: space-between; align-items: center; }
        .container { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; padding: 20px; }
        .panel { background: #252525; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
        h2 { color: #4CAF50; margin-top: 0; border-bottom: 1px solid #444; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
        .switch { position: relative; display: inline-block; width: 44px; height: 22px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #444; transition: .4s; border-radius: 22px; }
        input:checked + .slider { background-color: #4CAF50; }
        .slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider:before { transform: translateX(22px); }
        button { cursor: pointer; background: #444; color: white; border: none; padding: 5px 10px; border-radius: 4px; }
        button:hover { background: #555; }
    </style>
</head>
<body>
    <header>
        <h1>IDS/IPS DASHBOARD</h1>
        <div style="display:flex; align-items:center; gap:10px;">
            <span>Auto-Block (IPS)</span>
            <label class="switch">
                <input type="checkbox" id="ipsToggle" onchange="toggleIPS(this.checked)">
                <span class="slider"></span>
            </label>
        </div>
    </header>
    <div class="container">
        <div class="main-col">
            <div class="panel">
                <h2>Traffic Intensity by Attack Vector</h2>
                <div style="height: 250px;"><canvas id="intensityChart"></canvas></div>
            </div>
            <div class="panel">
                <h2>Live Alert Feed</h2>
                <table id="alerts">
                    <thead><tr><th>Time</th><th>Source</th><th>Signature</th><th>Action</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        <div class="side-col">
            <div class="panel">
                <h2>Active Firewall Blocks</h2>
                <table id="blocked-list">
                    <thead><tr><th>IP Address</th><th>Action</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>
    <script>
        const socket = io();
        const ctx = document.getElementById('intensityChart').getContext('2d');
    
    const colorMap = {
        'SYN_FLOOD': 'rgba(255, 77, 77, 0.5)',
        'PORT_SCAN': 'rgba(255, 174, 66, 0.5)',
        'HIGH_RATE': 'rgba(52, 152, 219, 0.5)',
        'UDP_FLOOD': 'rgba(230, 126, 34, 0.5)',
        'ICMP_FLOOD': 'rgba(155, 89, 182, 0.5)'
    };

    const intensityChart = new Chart(ctx, {
        type: 'line', // Changed to line for Area Chart effect
        data: { labels: [], datasets: [] },
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            elements: { point: { radius: 0 } }, // Removes dots for a cleaner look
            scales: { 
                x: { grid: { color: '#333' }, ticks: { color: '#888' } }, 
                y: { stacked: true, beginAtZero: true, grid: { color: '#333' } } 
            },
            plugins: { 
                legend: { position: 'top', labels: { color: '#eee', usePointStyle: true } } 
            }
        }
    });
    
        function toggleIPS(enabled) {
            fetch('/toggle_auto_block', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enabled: enabled})
            });
        }

        socket.on('new_alert', function(alert) {
            const tbody = document.querySelector('#alerts tbody');
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${new Date(alert.ts*1000).toLocaleTimeString()}</td>
                            <td>${alert.src_ip}</td><td>${alert.trigger}</td>
                            <td><button onclick="manageIP('block', '${alert.src_ip}')">Block</button></td>`;
            tbody.insertBefore(tr, tbody.firstChild);
        });

        socket.on('chart_update', function(data) {
        const timeLabel = new Date(data.ts * 1000).toLocaleTimeString();
        let dataset = intensityChart.data.datasets.find(d => d.label === data.type);
        
        if (!dataset) {
            dataset = { 
                label: data.type, 
                data: new Array(intensityChart.data.labels.length).fill(0), 
                backgroundColor: colorMap[data.type] || 'rgba(136, 136, 136, 0.5)',
                borderColor: colorMap[data.type]?.replace('0.5', '1') || '#888',
                fill: true, // This creates the Area effect
                tension: 0.4 // Smooth curves
            };
            intensityChart.data.datasets.push(dataset);
        }

        // Logic for updating labels and shifting data remains the same...
        if (!intensityChart.data.labels.includes(timeLabel)) {
            intensityChart.data.labels.push(timeLabel);
            intensityChart.data.datasets.forEach(d => d.data.push(d.label === data.type ? 1 : 0));
        } else {
            dataset.data[intensityChart.data.labels.indexOf(timeLabel)] += 1;
        }

        if (intensityChart.data.labels.length > 20) {
            intensityChart.data.labels.shift();
            intensityChart.data.datasets.forEach(d => d.data.shift());
        }
        intensityChart.update('none');
    });

        socket.on('update_blocks', function(ips) {
            const tbody = document.querySelector('#blocked-list tbody');
            tbody.innerHTML = ips.map(ip => `<tr><td>${ip}</td><td><button onclick="manageIP('unblock', '${ip}')">Release</button></td></tr>`).join('');
        });

        function manageIP(action, ip) { fetch(`/${action}/${ip}`, {method: 'POST'}); }
    </script>
</body>
</html>
"""

def block_logic(ip):
    if ip in blocked_ips: return
    cmd = config.BLOCK_CMD_TEMPLATE.format(ip=ip)
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        blocked_ips.add(ip)
        socketio.emit('update_blocks', list(blocked_ips))
        print(f"[SUCCESS] Firewall blocked: {ip}")
    except Exception as e:
        print(f"[ERROR] Firewall Command Failed: {e}")

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

@socketio.on('connect')
def handle_connect():
    socketio.emit('update_blocks', list(blocked_ips))

@app.route('/toggle_auto_block', methods=["POST"])
def toggle_auto_block():
    global auto_block_enabled
    auto_block_enabled = request.json.get('enabled', False)
    print(f"[IPS SYSTEM] Auto-Block: {'ON' if auto_block_enabled else 'OFF'}")
    return jsonify({"status": "success"})

@app.route('/block/<ip>', methods=["POST"])
def block_route(ip):
    block_logic(ip)
    return jsonify({"status": "success"})

@app.route('/unblock/<ip>', methods=["POST"])
def unblock_route(ip):
    cmd = config.UNBLOCK_CMD_TEMPLATE.format(ip=ip)
    try:
        subprocess.run(cmd, shell=True, check=True)
        blocked_ips.discard(ip)
        socketio.emit('update_blocks', list(blocked_ips))
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def push_alert(alert: Dict[str, Any]) -> None:
    global auto_block_enabled
    if alert.get("severity") not in ["CRITICAL", "WARNING"]: return
    
    socketio.emit('new_alert', alert)
    socketio.emit('chart_update', {"ts": alert['ts'], "type": alert['trigger']})

    if auto_block_enabled and alert.get("severity") == "CRITICAL":
        print(f"[IPS ACTION] Critical threat detected from {alert['src_ip']}. Auto-blocking...")
        block_logic(alert.get("src_ip"))