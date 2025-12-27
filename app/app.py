from flask import Flask, render_template_string, request, jsonify, Response
import os
import json
from datetime import datetime, timedelta
import platform
import psutil
import socket
import redis
import threading
import time
from collections import deque
from dotenv import load_dotenv
import sys
import boto3
import traceback

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ===== LOAD CONFIG FROM .env =====
SECRET_KEY = os.getenv('SECRET_KEY', '57d27fe43e260cc4083c7d77d')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
METRICS_INTERVAL = int(os.getenv('METRICS_INTERVAL', 5))
ALERT_CPU_THRESHOLD = float(os.getenv('ALERT_CPU_THRESHOLD', 80))
ALERT_MEMORY_THRESHOLD = float(os.getenv('ALERT_MEMORY_THRESHOLD', 85))
ALERT_DISK_THRESHOLD = float(os.getenv('ALERT_DISK_THRESHOLD', 90))
AWS_REGION = os.getenv('AWS_REGION', 'ap-south-1')
FARGATE_CPU_PRICE = float(os.getenv('FARGATE_CPU_PRICE', 0.04048))
FARGATE_MEMORY_PRICE = float(os.getenv('FARGATE_MEMORY_PRICE', 0.00445))

app.config['SECRET_KEY'] = SECRET_KEY

# ==================== AWS AUDIT INTEGRATION ====================
print("=" * 70)
print("🔍 INITIALIZING AWS AUDIT")
print("=" * 70)

AWS_AUDIT_AVAILABLE = False
aws_audit = None

try:
    # Test AWS credentials first
    if not os.getenv('AWS_DEFAULT_REGION'):
        os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    
    session = boto3.Session()
    sts = session.client('sts')
    identity = sts.get_caller_identity()
    print(f"✅ AWS Account: {identity['Account']}")
    print(f"✅ AWS Region: {session.region_name}")
    
    try:
        # Direct import
        from aws_audit import AWSComprehensiveAuditor as AWSAudit
        print("✅ Successfully imported AWSAudit from aws_audit.py")
    except ImportError as e:
        print(f"❌ Direct import failed: {e}")
        print("Trying alternative import method...")
        
        # Try importing using importlib
        import importlib.util
        current_dir = os.path.dirname(os.path.abspath(__file__))
        aws_audit_path = os.path.join(current_dir, "aws_audit.py")
        
        if os.path.exists(aws_audit_path):
            spec = importlib.util.spec_from_file_location("aws_audit", aws_audit_path)
            aws_audit_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(aws_audit_module)
            AWSAudit = aws_audit_module.AWSComprehensiveAuditor
            print("✅ Imported AWSComprehensiveAuditor using importlib")
        else:
            print(f"❌ aws_audit.py not found at: {aws_audit_path}")
            raise
    
    # Create instance
    aws_audit = AWSAudit()
    AWS_AUDIT_AVAILABLE = True
    
    # Test the audit - try different method names
    print("🔍 Testing AWS audit...")
    
    # Check what methods are available
    available_methods = [m for m in dir(aws_audit) if not m.startswith('_') and 'audit' in m.lower() or 'run' in m.lower()]
    print(f"Available audit methods: {available_methods}")
    
    # Try different possible method names
    test_success = False
    
    # Try run_complete_audit first (from AWSComprehensiveAuditor)
    if hasattr(aws_audit, 'run_complete_audit'):
        try:
            test_result = aws_audit.run_complete_audit()
            if 'error' not in test_result:
                savings = test_result.get('summary', {}).get('estimated_monthly_savings', 0)
                print(f"✅ AWS Audit working! Potential savings: ${savings:.2f}/month")
                test_success = True
        except Exception as e:
            print(f"⚠️ run_complete_audit failed: {e}")
    
    # Try get_structured_audit (old method name)
    if not test_success and hasattr(aws_audit, 'get_structured_audit'):
        try:
            test_result = aws_audit.get_structured_audit()
            if 'error' not in test_result:
                savings = test_result.get('cost_analysis', {}).get('total_potential_savings', 0)
                print(f"✅ AWS Audit working! Potential savings: ${savings}/month")
                test_success = True
        except Exception as e:
            print(f"⚠️ get_structured_audit failed: {e}")
    
    # Try individual audit methods
    if not test_success and hasattr(aws_audit, 'audit_ec2_resources'):
        try:
            ec2_result = aws_audit.audit_ec2_resources()
            if 'error' not in ec2_result:
                instances = ec2_result.get('instances', {}).get('total', 0)
                print(f"✅ AWS Audit partially working! Found {instances} EC2 instances")
                test_success = True
        except Exception as e:
            print(f"⚠️ Individual audit failed: {e}")
    
    if test_success:
        print(f"✅ AWS Audit status: ACTIVE")
    else:
        print(f"⚠️ AWS Audit status: LIMITED")
        print("💡 Some audit features may not be available")
    
except Exception as e:
    print(f"❌ AWS Audit initialization failed: {e}")
    AWS_AUDIT_AVAILABLE = False
    aws_audit = None

print("=" * 70)

# ===== REAL-TIME MONITORING SYSTEM =====
class RealTimeMonitor:
    def __init__(self):
        self.start_time = datetime.now()
        self.visitors = 0
        self.visitor_details = []
        
        # Store history (5-second intervals, 1 hour of data)
        max_history = 720
        self.cpu_history = deque(maxlen=max_history)
        self.memory_history = deque(maxlen=max_history)
        self.disk_history = deque(maxlen=max_history)
        
        # Current metrics
        self.current_metrics = {
            'cpu': 0.0,
            'memory': 0.0,
            'disk': 0.0,
            'cpu_cores': 0,
            'memory_total': 0.0,
            'memory_used': 0.0,
            'disk_total': 0.0,
            'disk_used': 0.0,
            'app_memory_mb': 0.0,
            'network_sent_kbs': 0.0,
            'network_recv_kbs': 0.0,
            'process_count': 0,
            'connections': 0
        }
        
        # Network stats for speed calculation
        self.last_net_io = psutil.net_io_counters()
        self.last_net_time = time.time()
        
        # Start background thread
        self._start_monitoring_thread()
        print("✅ Real-time monitoring started")
    
    def _start_monitoring_thread(self):
        """Background thread for real metrics"""
        def monitor():
            while True:
                try:
                    # Get real CPU (all cores)
                    cpu_percent = psutil.cpu_percent(interval=0.5, percpu=True)
                    cpu_avg = sum(cpu_percent) / len(cpu_percent)
                    
                    # Get real memory
                    memory = psutil.virtual_memory()
                    
                    # Get real disk
                    disk = psutil.disk_usage('/')
                    
                    # Get network speed
                    current_net_io = psutil.net_io_counters()
                    current_time = time.time()
                    time_diff = current_time - self.last_net_time
                    
                    if time_diff > 0:
                        sent_speed = (current_net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff / 1024  # KB/s
                        recv_speed = (current_net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff / 1024
                        self.last_net_io = current_net_io
                        self.last_net_time = current_time
                    else:
                        sent_speed = 0.0
                        recv_speed = 0.0
                    
                    # Get Flask process memory
                    try:
                        process = psutil.Process()
                        app_memory = process.memory_info().rss / 1024 / 1024  # MB
                    except:
                        app_memory = 0.0
                    
                    # Store in history
                    timestamp = datetime.now().isoformat()
                    self.cpu_history.append({'time': timestamp, 'value': cpu_avg})
                    self.memory_history.append({'time': timestamp, 'value': memory.percent})
                    self.disk_history.append({'time': timestamp, 'value': disk.percent})
                    
                    # Update current metrics
                    self.current_metrics = {
                        'timestamp': timestamp,
                        'cpu': round(cpu_avg, 2),
                        'memory': round(memory.percent, 2),
                        'disk': round(disk.percent, 2),
                        'cpu_cores': psutil.cpu_count(logical=True),
                        'memory_total': round(memory.total / (1024**3), 2),
                        'memory_used': round(memory.used / (1024**3), 2),
                        'disk_total': round(disk.total / (1024**3), 2),
                        'disk_used': round(disk.used / (1024**3), 2),
                        'app_memory_mb': round(app_memory, 2),
                        'network_sent_kbs': round(sent_speed, 2),
                        'network_recv_kbs': round(recv_speed, 2),
                        'process_count': len(psutil.pids()),
                        'connections': len(psutil.net_connections()),
                        'cpu_per_core': [round(c, 2) for c in cpu_percent]
                    }
                    
                except Exception as e:
                    print(f"Monitoring error: {e}")
                
                time.sleep(METRICS_INTERVAL)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def get_metrics(self):
        """Get comprehensive real metrics"""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            return {
                **self.current_metrics,
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'boot_time': boot_time.isoformat(),
                'system_uptime': str(uptime).split('.')[0],
                'app_uptime': str(datetime.now() - self.start_time).split('.')[0],
                'python_version': platform.python_version(),
                'flask_visitors': self.visitors,
                'alert_thresholds': {
                    'cpu': ALERT_CPU_THRESHOLD,
                    'memory': ALERT_MEMORY_THRESHOLD,
                    'disk': ALERT_DISK_THRESHOLD
                }
            }
        except Exception as e:
            print(f"Error getting metrics: {e}")
            return self._get_default_metrics()
    
    def _get_default_metrics(self):
        """Fallback metrics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu': 0.0,
            'memory': 0.0,
            'disk': 0.0,
            'cpu_cores': 0,
            'memory_total': 0.0,
            'memory_used': 0.0,
            'disk_total': 0.0,
            'disk_used': 0.0,
            'app_memory_mb': 0.0,
            'network_sent_kbs': 0.0,
            'network_recv_kbs': 0.0,
            'process_count': 0,
            'connections': 0,
            'hostname': 'unknown',
            'platform': platform.platform(),
            'system_uptime': '0:00:00',
            'app_uptime': '0:00:00',
            'python_version': platform.python_version(),
            'flask_visitors': self.visitors
        }
    
    def get_history(self):
        """Get historical data for charts"""
        return {
            'cpu': list(self.cpu_history)[-60:],  # Last 5 minutes
            'memory': list(self.memory_history)[-60:],
            'disk': list(self.disk_history)[-60:]
        }
    
    def increment_visitor(self, ip=None, user_agent=None):
        """Increment visitor count with details"""
        self.visitors += 1
        visit_info = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip or 'unknown',
            'user_agent': (user_agent or 'unknown')[:100],
            'visitor_number': self.visitors
        }
        self.visitor_details.append(visit_info)
        if len(self.visitor_details) > 50:
            self.visitor_details.pop(0)
        return self.visitors
    
    def get_alerts(self):
        """Check for system alerts"""
        metrics = self.current_metrics
        alerts = []
        
        if metrics['cpu'] > ALERT_CPU_THRESHOLD:
            alerts.append({
                'level': 'WARNING' if metrics['cpu'] < 90 else 'CRITICAL',
                'message': f'High CPU usage: {metrics["cpu"]}%',
                'metric': 'cpu',
                'value': metrics['cpu'],
                'threshold': ALERT_CPU_THRESHOLD
            })
        
        if metrics['memory'] > ALERT_MEMORY_THRESHOLD:
            alerts.append({
                'level': 'WARNING' if metrics['memory'] < 95 else 'CRITICAL',
                'message': f'High Memory usage: {metrics["memory"]}%',
                'metric': 'memory',
                'value': metrics['memory'],
                'threshold': ALERT_MEMORY_THRESHOLD
            })
        
        if metrics['disk'] > ALERT_DISK_THRESHOLD:
            alerts.append({
                'level': 'CRITICAL',
                'message': f'High Disk usage: {metrics["disk"]}%',
                'metric': 'disk',
                'value': metrics['disk'],
                'threshold': ALERT_DISK_THRESHOLD
            })
        
        return alerts

# Initialize monitor
monitor = RealTimeMonitor()

# ===== REDIS CONNECTION =====
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD if REDIS_PASSWORD else None,
        decode_responses=True,
        socket_connect_timeout=3
    )
    redis_client.ping()
    REDIS_AVAILABLE = True
    print(f"✅ Redis connected to {REDIS_HOST}:{REDIS_PORT}")
except Exception as e:
    print(f"❌ Redis connection failed: {e}")
    REDIS_AVAILABLE = False
    # Fallback memory store
    class MemoryStore:
        def __init__(self):
            self.data = {'visitor_count': 0, 'recent_visits': []}
        def incr(self, key):
            self.data[key] = self.data.get(key, 0) + 1
            return self.data[key]
        def get(self, key, default=None):
            return self.data.get(key, default)
        def set(self, key, value):
            self.data[key] = value
        def lpush(self, key, value):
            if key not in self.data:
                self.data[key] = []
            self.data[key].insert(0, value)
        def lrange(self, key, start, end):
            if key in self.data:
                return self.data[key][start:end+1]
            return []
        def ltrim(self, key, start, end):
            if key in self.data:
                self.data[key] = self.data[key][start:end+1]
    redis_client = MemoryStore()

# ===== HELPER FUNCTIONS =====
def increment_visitor_counter():
    """Track visitors with Redis or in-memory"""
    try:
        count = redis_client.incr('visitor_count')
        visit_info = {
            'timestamp': datetime.now().isoformat(),
            'user_agent': request.headers.get('User-Agent', 'Unknown')[:100],
            'ip': request.remote_addr
        }
        redis_client.lpush('recent_visits', json.dumps(visit_info))
        redis_client.ltrim('recent_visits', 0, 49)
        
        # Also track in monitor for real-time display
        monitor.increment_visitor(request.remote_addr, request.headers.get('User-Agent'))
        
        return count
    except:
        # Fallback to in-memory tracking
        return monitor.increment_visitor(request.remote_addr, request.headers.get('User-Agent'))

def get_redis_status():
    """Get Redis connection status"""
    if REDIS_AVAILABLE:
        try:
            redis_client.ping()
            return "Connected"
        except:
            return "Disconnected"
    return "In-Memory"

# ===== HTML TEMPLATE =====
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Python Flask on AWS EKS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { font-family: 'Inter', sans-serif; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover { transition: all 0.3s ease; }
        .card-hover:hover { transform: translateY(-5px); box-shadow: 0 20px 40px rgba(0,0,0,0.1); }
        .pulse-animation { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .progress-bar { transition: width 0.5s ease; }
        .chart-container { height: 200px; position: relative; }
        .alert-critical { background: linear-gradient(135deg, #f56565 0%, #c53030 100%); }
        .alert-warning { background: linear-gradient(135deg, #ed8936 0%, #c05621 100%); }
    </style>
</head>
<body class="gradient-bg min-h-screen p-4">
    <div class="w-full max-w-7xl mx-auto">
        <!-- Header -->
        <div class="bg-white rounded-2xl shadow-2xl overflow-hidden mb-8">
            <div class="bg-gradient-to-r from-indigo-600 to-purple-600 text-white p-8 md:p-12">
                <div class="flex flex-col md:flex-row items-center justify-between gap-6 mb-6">
                    <div class="flex items-center gap-6">
                        <div class="text-5xl">
                            <i class="fas fa-rocket"></i>
                            <i class="fas fa-docker ml-4"></i>
                            <i class="fas fa-cloud ml-4"></i>
                        </div>
                        <div>
                            <h1 class="text-4xl md:text-5xl font-bold mb-3">Python Flask on AWS EKS</h1>
                            <p class="text-xl opacity-90">Containerized Web App with Docker & AWS EKS</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <div class="text-sm opacity-80">Last Updated: <span id="last-updated">{{ current_time }}</span></div>
                        <div class="text-sm opacity-80">Status: <span class="font-bold text-green-300">LIVE</span></div>
                    </div>
                </div>
                <div class="inline-flex items-center space-x-4 text-lg">
                    <span class="bg-white/20 px-4 py-2 rounded-full">
                        <i class="fas fa-code mr-2"></i>Python {{ python_version }}
                    </span>
                    <span class="bg-white/20 px-4 py-2 rounded-full">
                        <i class="fas fa-cube mr-2"></i>Docker Container
                    </span>
                    <span class="bg-white/20 px-4 py-2 rounded-full">
                        <i class="fas fa-server mr-2"></i>AWS EKS
                    </span>
                    <span class="bg-white/20 px-4 py-2 rounded-full">
                        <i class="fas fa-chart-line mr-2"></i>Real-time Metrics
                    </span>
                </div>
            </div>

            <!-- Alert Banner -->
            <div id="alert-container" class="p-4"></div>

            <!-- Main Content -->
            <div class="p-8 md:p-12">
                <!-- REAL-TIME METRICS CARDS -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
                    <!-- CPU Card -->
                    <div class="card-hover bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-6 border border-blue-100">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <div class="text-2xl font-bold text-blue-700" id="real-cpu">0.0%</div>
                                <p class="text-gray-600 text-sm">CPU Usage</p>
                                <p class="text-xs text-gray-500" id="cpu-cores">Cores: Loading...</p>
                            </div>
                            <div class="bg-blue-100 p-3 rounded-xl">
                                <i class="fas fa-microchip text-blue-600 text-2xl"></i>
                            </div>
                        </div>
                        <div class="w-full bg-blue-200 rounded-full h-2">
                            <div class="bg-blue-600 h-2 rounded-full progress-bar" id="cpu-progress" style="width: 0%"></div>
                        </div>
                        <div class="mt-2 text-xs text-gray-500" id="cpu-details">Per core: Loading...</div>
                    </div>

                    <!-- Memory Card -->
                    <div class="card-hover bg-gradient-to-br from-green-50 to-emerald-50 rounded-2xl p-6 border border-green-100">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <div class="text-2xl font-bold text-green-700" id="real-memory">0.0%</div>
                                <p class="text-gray-600 text-sm">Memory Used</p>
                                <p class="text-xs text-gray-500" id="memory-details">0.0/0.0 GB</p>
                            </div>
                            <div class="bg-green-100 p-3 rounded-xl">
                                <i class="fas fa-memory text-green-600 text-2xl"></i>
                            </div>
                        </div>
                        <div class="w-full bg-green-200 rounded-full h-2">
                            <div class="bg-green-600 h-2 rounded-full progress-bar" id="memory-progress" style="width: 0%"></div>
                        </div>
                        <div class="mt-2 text-xs text-gray-500" id="app-memory">App: 0.0 MB</div>
                    </div>

                    <!-- Disk Card -->
                    <div class="card-hover bg-gradient-to-br from-purple-50 to-pink-50 rounded-2xl p-6 border border-purple-100">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <div class="text-2xl font-bold text-purple-700" id="real-disk">0.0%</div>
                                <p class="text-gray-600 text-sm">Disk Usage</p>
                                <p class="text-xs text-gray-500" id="disk-details">0.0/0.0 GB</p>
                            </div>
                            <div class="bg-purple-100 p-3 rounded-xl">
                                <i class="fas fa-hdd text-purple-600 text-2xl"></i>
                            </div>
                        </div>
                        <div class="w-full bg-purple-200 rounded-full h-2">
                            <div class="bg-purple-600 h-2 rounded-full progress-bar" id="disk-progress" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Visitors Card -->
                    <div class="card-hover bg-gradient-to-br from-orange-50 to-red-50 rounded-2xl p-6 border border-orange-100">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <div class="text-2xl font-bold text-orange-700" id="real-visitors">{{ visitor_count }}</div>
                                <p class="text-gray-600 text-sm">Total Visitors</p>
                                <p class="text-xs text-gray-500">Real-time: <span id="flask-visitors">0</span></p>
                            </div>
                            <div class="bg-orange-100 p-3 rounded-xl">
                                <i class="fas fa-users text-orange-600 text-2xl"></i>
                            </div>
                        </div>
                        <p class="text-sm" id="redis-status">
                            <i class="fas fa-circle mr-1 {{ 'text-green-500' if redis_status == 'Connected' else 'text-yellow-500' }}"></i>
                            {{ redis_status }}
                        </p>
                        <div class="mt-2 text-xs text-gray-500" id="network-speed">Network: 0.0/0.0 KB/s</div>
                    </div>
                </div>

                <!-- REAL-TIME CHARTS -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-10">
                    <div class="card-hover bg-white rounded-2xl p-6 border border-gray-200">
                        <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
                            <i class="fas fa-microchip text-blue-500 mr-2"></i>CPU Usage History
                        </h3>
                        <div class="chart-container">
                            <canvas id="cpu-chart"></canvas>
                        </div>
                    </div>
                    <div class="card-hover bg-white rounded-2xl p-6 border border-gray-200">
                        <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
                            <i class="fas fa-memory text-green-500 mr-2"></i>Memory Usage History
                        </h3>
                        <div class="chart-container">
                            <canvas id="memory-chart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- AWS Cost & Audit Section -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
                    <!-- AWS Cost Calculator -->
                    <div class="bg-gradient-to-r from-gray-50 to-white rounded-2xl p-8 border border-gray-200">
                        <h2 class="text-3xl font-bold text-gray-800 mb-6 flex items-center">
                            <i class="fas fa-calculator text-red-500 mr-3"></i>AWS Cost Calculator
                        </h2>
                        
                        <div class="space-y-6">
                            <div>
                                <label class="block text-gray-700 mb-2">
                                    <i class="fas fa-microchip text-blue-500 mr-2"></i>
                                    vCPU: <span id="cpuValue" class="font-bold">0.25</span> cores
                                </label>
                                <input type="range" min="0.25" max="4" step="0.25" value="0.25" 
                                       class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                                       oninput="updateCost()" id="cpuSlider">
                            </div>
                            
                            <div>
                                <label class="block text-gray-700 mb-2">
                                    <i class="fas fa-memory text-green-500 mr-2"></i>
                                    Memory: <span id="memoryValue" class="font-bold">0.5</span> GB
                                </label>
                                <input type="range" min="0.5" max="16" step="0.5" value="0.5" 
                                       class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                                       oninput="updateCost()" id="memorySlider">
                            </div>
                            
                            <div class="pt-4 border-t">
                                <p class="text-sm text-gray-600">
                                    <i class="fas fa-info-circle text-blue-500 mr-2"></i>
                                    Based on AWS Fargate pricing ({{ aws_region }})
                                </p>
                            </div>
                        </div>
                        
                        <!-- Cost Results -->
                        <div class="space-y-4 mt-6">
                            <div class="flex justify-between items-center p-4 bg-blue-50 rounded-xl">
                                <div>
                                    <p class="font-medium text-gray-700">Hourly Cost</p>
                                    <p class="text-sm text-gray-500">Per pod</p>
                                </div>
                                <div class="text-2xl font-bold text-blue-600">$<span id="hourlyCost">0.010</span></div>
                            </div>
                            
                            <div class="flex justify-between items-center p-4 bg-green-50 rounded-xl">
                                <div>
                                    <p class="font-medium text-gray-700">Daily Cost</p>
                                    <p class="text-sm text-gray-500">24 hours</p>
                                </div>
                                <div class="text-2xl font-bold text-green-600">$<span id="dailyCost">0.24</span></div>
                            </div>
                            
                            <div class="flex justify-between items-center p-4 bg-purple-50 rounded-xl">
                                <div>
                                    <p class="font-medium text-gray-700">Monthly Cost</p>
                                    <p class="text-sm text-gray-500">30 days</p>
                                </div>
                                <div class="text-2xl font-bold text-purple-600">$<span id="monthlyCost">7.20</span></div>
                            </div>
                        </div>
                    </div>

                    <!-- AWS Audit Panel -->
                    <div class="bg-gradient-to-r from-gray-50 to-white rounded-2xl p-8 border border-gray-200">
                        <h2 class="text-3xl font-bold text-gray-800 mb-6 flex items-center">
                            <i class="fas fa-search-dollar text-green-500 mr-3"></i>AWS Cost Audit
                        </h2>
                        
                        <div class="space-y-6">
                            <div class="text-center">
                                <div class="text-5xl font-bold text-gray-800 mb-2" id="aws-cost">$0</div>
                                <p class="text-gray-600">Potential Monthly Savings</p>
                                <p class="text-sm text-gray-500" id="aws-issues">0 issues found</p>
                            </div>
                            
                            <div class="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
                                <div class="flex items-center mb-2">
                                    <i class="fas fa-lightbulb text-yellow-500 mr-2"></i>
                                    <h4 class="font-bold text-gray-700">Quick Audit</h4>
                                </div>
                                <p class="text-sm text-gray-600 mb-4">
                                    Scan for unattached resources that are costing you money
                                </p>
                                <button onclick="runAWSAudit()" class="w-full bg-yellow-500 hover:bg-yellow-600 text-white font-medium py-3 rounded-xl transition flex items-center justify-center">
                                    <i class="fas fa-play mr-3"></i>Run AWS Cost Audit
                                </button>
                            </div>
                            
                            <div class="grid grid-cols-3 gap-4">
                                <a href="/api/aws/audit/quick" target="_blank" class="inline-flex items-center justify-center bg-blue-500 hover:bg-blue-600 text-white font-medium px-4 py-2 rounded-lg transition text-sm">
                                    <i class="fas fa-bolt mr-2"></i>Quick
                                </a>
                                <a href="/api/aws/audit" target="_blank" class="inline-flex items-center justify-center bg-green-500 hover:bg-green-600 text-white font-medium px-4 py-2 rounded-lg transition text-sm">
                                    <i class="fas fa-search mr-2"></i>Full
                                </a>
                                <a href="/api/aws/audit/structured" target="_blank" class="inline-flex items-center justify-center bg-purple-500 hover:bg-purple-600 text-white font-medium px-4 py-2 rounded-lg transition text-sm">
                                    <i class="fas fa-list mr-2"></i>Structured
                                </a>
                            </div>
                            
                            <div class="text-xs text-gray-500 pt-4 border-t">
                                <i class="fas fa-info-circle mr-1"></i>
                                AWS Audit requires AWS credentials with read-only permissions
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Info Cards -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                    <!-- System Info -->
                    <div class="card-hover bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-6 border border-blue-100">
                        <div class="flex items-center mb-4">
                            <div class="bg-blue-100 p-3 rounded-xl mr-4">
                                <i class="fas fa-server text-blue-600 text-2xl"></i>
                            </div>
                            <h3 class="text-xl font-bold text-gray-800">System Info</h3>
                        </div>
                        <p class="text-gray-600 mb-2"><i class="fas fa-hashtag text-blue-500 mr-2"></i>
                            <span class="font-medium">Host:</span> <span id="real-hostname">{{ hostname }}</span>
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-microchip text-blue-500 mr-2"></i>
                            <span class="font-medium">Platform:</span> <span id="real-platform">{{ platform }}</span>
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-clock text-blue-500 mr-2"></i>
                            <span class="font-medium">System Uptime:</span> <span id="system-uptime">Loading...</span>
                        </p>
                        <p class="text-gray-600"><i class="fas fa-play text-blue-500 mr-2"></i>
                            <span class="font-medium">App Uptime:</span> <span id="app-uptime">Loading...</span>
                        </p>
                    </div>

                    <!-- App Status -->
                    <div class="card-hover bg-gradient-to-br from-green-50 to-emerald-50 rounded-2xl p-6 border border-green-100">
                        <div class="flex items-center mb-4">
                            <div class="bg-green-100 p-3 rounded-xl mr-4">
                                <i class="fas fa-shield-alt text-green-600 text-2xl"></i>
                            </div>
                            <h3 class="text-xl font-bold text-gray-800">App Status</h3>
                        </div>
                        <div class="flex items-center mb-4">
                            <div class="pulse-animation bg-green-500 w-3 h-3 rounded-full mr-3"></div>
                            <span class="text-lg font-bold text-green-700">All Systems Operational</span>
                        </div>
                        <p class="text-gray-600 mb-2"><i class="fas fa-check-circle text-green-500 mr-2"></i>
                            Docker Container: <span class="font-medium">Running</span>
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-check-circle text-green-500 mr-2"></i>
                            Flask Server: <span class="font-medium">Active</span>
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-database text-green-500 mr-2"></i>
                            Redis: <span class="font-medium" id="redis-status-text">{{ redis_status }}</span>
                        </p>
                        <p class="text-gray-600"><i class="fas fa-heartbeat text-green-500 mr-2"></i>
                            Health Check: <span class="font-medium">PASS</span>
                        </p>
                    </div>

                    <!-- Deployment Info -->
                    <div class="card-hover bg-gradient-to-br from-purple-50 to-pink-50 rounded-2xl p-6 border border-purple-100">
                        <div class="flex items-center mb-4">
                            <div class="bg-purple-100 p-3 rounded-xl mr-4">
                                <i class="fas fa-cloud-upload-alt text-purple-600 text-2xl"></i>
                            </div>
                            <h3 class="text-xl font-bold text-gray-800">Deployment</h3>
                        </div>
                        <p class="text-gray-600 mb-2"><i class="fas fa-cloud text-purple-500 mr-2"></i>
                            <span class="font-medium">Platform:</span> AWS EKS
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-map-marker-alt text-purple-500 mr-2"></i>
                            <span class="font-medium">Region:</span> {{ aws_region }}
                        </p>
                        <p class="text-gray-600 mb-2"><i class="fas fa-cube text-purple-500 mr-2"></i>
                            <span class="font-medium">Container:</span> Docker
                        </p>
                        <p class="text-gray-600"><i class="fas fa-chart-bar text-purple-500 mr-2"></i>
                            <span class="font-medium">Metrics:</span> Real-time
                        </p>
                    </div>
                </div>

                <!-- API Endpoints -->
                <div class="mb-10">
                    <h2 class="text-3xl font-bold text-gray-800 mb-6 flex items-center">
                        <i class="fas fa-plug text-indigo-600 mr-3"></i>API Endpoints
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <a href="/" class="card-hover block">
                            <div class="bg-white border border-gray-200 rounded-xl p-6 hover:border-indigo-300 hover:shadow-lg">
                                <div class="flex items-center mb-4">
                                    <div class="bg-indigo-100 p-3 rounded-lg mr-4">
                                        <i class="fas fa-home text-indigo-600 text-xl"></i>
                                    </div>
                                    <h3 class="text-xl font-bold text-gray-800">Dashboard</h3>
                                </div>
                                <p class="text-gray-600 mb-4">Real-time monitoring dashboard</p>
                                <code class="bg-gray-100 text-gray-800 px-3 py-1 rounded text-sm">GET /</code>
                            </div>
                        </a>

                        <a href="/health" class="card-hover block">
                            <div class="bg-white border border-gray-200 rounded-xl p-6 hover:border-green-300 hover:shadow-lg">
                                <div class="flex items-center mb-4">
                                    <div class="bg-green-100 p-3 rounded-lg mr-4">
                                        <i class="fas fa-heartbeat text-green-600 text-xl"></i>
                                    </div>
                                    <h3 class="text-xl font-bold text-gray-800">Health Check</h3>
                                </div>
                                <p class="text-gray-600 mb-4">System health status with metrics</p>
                                <code class="bg-gray-100 text-gray-800 px-3 py-1 rounded text-sm">GET /health</code>
                            </div>
                        </a>

                        <a href="/api/real-metrics" class="card-hover block">
                            <div class="bg-white border border-gray-200 rounded-xl p-6 hover:border-blue-300 hover:shadow-lg">
                                <div class="flex items-center mb-4">
                                    <div class="bg-blue-100 p-3 rounded-lg mr-4">
                                        <i class="fas fa-chart-line text-blue-600 text-xl"></i>
                                    </div>
                                    <h3 class="text-xl font-bold text-gray-800">Live Metrics</h3>
                                </div>
                                <p class="text-gray-600 mb-4">Real-time system metrics (JSON)</p>
                                <code class="bg-gray-100 text-gray-800 px-3 py-1 rounded text-sm">GET /api/real-metrics</code>
                            </div>
                        </a>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="bg-gradient-to-r from-gray-50 to-white rounded-2xl p-8 border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-6 flex items-center">
                        <i class="fas fa-bolt text-yellow-500 mr-3"></i>Quick Actions
                    </h2>
                    <div class="flex flex-wrap gap-4">
                        <button onclick="refreshMetrics()" class="inline-flex items-center bg-blue-500 hover:bg-blue-600 text-white font-medium px-6 py-3 rounded-xl transition">
                            <i class="fas fa-sync-alt mr-3"></i>Refresh Metrics
                        </button>
                        <a href="/health" class="inline-flex items-center bg-green-500 hover:bg-green-600 text-white font-medium px-6 py-3 rounded-xl transition">
                            <i class="fas fa-heartbeat mr-3"></i>Check Health
                        </a>
                        <a href="/api/real-metrics" target="_blank" class="inline-flex items-center bg-purple-500 hover:bg-purple-600 text-white font-medium px-6 py-3 rounded-xl transition">
                            <i class="fas fa-code mr-3"></i>View JSON API
                        </a>
                        <button onclick="toggleAutoRefresh()" id="auto-refresh-btn" class="inline-flex items-center bg-yellow-500 hover:bg-yellow-600 text-white font-medium px-6 py-3 rounded-xl transition">
                            <i class="fas fa-play mr-3"></i>Auto-Refresh: ON
                        </button>
                    </div>
                </div>
            </div>

            <!-- Footer -->
            <div class="bg-gray-900 text-gray-300 p-6 text-center">
                <div class="flex flex-col md:flex-row justify-between items-center">
                    <div class="mb-4 md:mb-0">
                        <p class="text-lg font-medium">🚀 DevOps Learning Project</p>
                        <p class="text-sm opacity-80">Containerized Python Flask on AWS EKS</p>
                    </div>
                    <div class="flex space-x-6 text-2xl">
                        <i class="fab fa-python hover:text-white transition" title="Python"></i>
                        <i class="fab fa-docker hover:text-white transition" title="Docker"></i>
                        <i class="fab fa-aws hover:text-white transition" title="AWS"></i>
                        <i class="fas fa-chart-line hover:text-white transition" title="Real-time Metrics"></i>
                        <i class="fas fa-calculator hover:text-white transition" title="Cost Calculator"></i>
                    </div>
                </div>
                <p class="mt-4 text-sm opacity-70">Deployed via Docker + AWS EKS + Flask + Real-time Monitoring</p>
                <p class="text-xs opacity-50 mt-2">
                    <span id="live-status">Live Metrics: Active</span> | 
                    Visitors: <span id="footer-visitors">{{ visitor_count }}</span> | 
                    Updated: <span id="footer-time">{{ current_time }}</span>
                </p>
            </div>
        </div>
    </div>

    <script>
        // Initialize charts
        let cpuChart, memoryChart;
        let autoRefresh = true;
        let refreshInterval;
        
        function initCharts() {
            const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
            cpuChart = new Chart(cpuCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'CPU %',
                        data: [],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { 
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(0,0,0,0.05)' }
                        },
                        x: { grid: { display: false } }
                    }
                }
            });
            
            const memoryCtx = document.getElementById('memory-chart').getContext('2d');
            memoryChart = new Chart(memoryCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Memory %',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { 
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(0,0,0,0.05)' }
                        },
                        x: { grid: { display: false } }
                    }
                }
            });
        }
        
        // Update metrics
        async function updateRealTimeMetrics() {
            try {
                const response = await fetch('/api/real-metrics');
                const data = await response.json();
                
                if (data.error) {
                    console.error('Error:', data.error);
                    return;
                }
                
                // Update CPU
                document.getElementById('real-cpu').textContent = data.cpu + '%';
                document.getElementById('cpu-progress').style.width = data.cpu + '%';
                document.getElementById('cpu-cores').textContent = 'Cores: ' + data.cpu_cores;
                if (data.cpu_per_core) {
                    document.getElementById('cpu-details').textContent = 
                        'Per core: ' + data.cpu_per_core.join('%, ') + '%';
                }
                
                // Update Memory
                document.getElementById('real-memory').textContent = data.memory + '%';
                document.getElementById('memory-progress').style.width = data.memory + '%';
                document.getElementById('memory-details').textContent = 
                    data.memory_used + '/' + data.memory_total + ' GB';
                document.getElementById('app-memory').textContent = 
                    'App: ' + data.app_memory_mb + ' MB';
                
                // Update Disk
                document.getElementById('real-disk').textContent = data.disk + '%';
                document.getElementById('disk-progress').style.width = data.disk + '%';
                document.getElementById('disk-details').textContent = 
                    data.disk_used + '/' + data.disk_total + ' GB';
                
                // Update System Info
                document.getElementById('real-hostname').textContent = data.hostname;
                document.getElementById('real-platform').textContent = data.platform;
                document.getElementById('system-uptime').textContent = data.system_uptime;
                document.getElementById('app-uptime').textContent = data.app_uptime;
                document.getElementById('flask-visitors').textContent = data.flask_visitors || 0;
                
                // Update Network
                document.getElementById('network-speed').textContent = 
                    'Network: ↑' + data.network_sent_kbs + ' ↓' + data.network_recv_kbs + ' KB/s';
                
                // Update timestamp
                const now = new Date();
                document.getElementById('last-updated').textContent = now.toLocaleTimeString();
                document.getElementById('footer-time').textContent = now.toLocaleTimeString();
                document.getElementById('footer-visitors').textContent = data.flask_visitors || document.getElementById('real-visitors').textContent;
                
                // Update Redis status
                const redisStatus = document.getElementById('redis-status-text');
                if (redisStatus) {
                    redisStatus.textContent = data.redis_connected ? 'Connected' : 'In-Memory';
                }
                
                // Check for alerts
                checkAlerts(data);
                
                // Update charts
                updateCharts();
                
            } catch (error) {
                console.error('Error fetching metrics:', error);
                document.getElementById('last-updated').textContent = 'Error: ' + new Date().toLocaleTimeString();
            }
        }
        
        // Update charts with history
        async function updateCharts() {
            try {
                const response = await fetch('/api/metrics/history');
                const history = await response.json();
                
                if (history.cpu && cpuChart) {
                    const times = history.cpu.slice(-20).map(h => 
                        new Date(h.time).toLocaleTimeString().substring(0, 5));
                    const values = history.cpu.slice(-20).map(h => h.value);
                    
                    cpuChart.data.labels = times;
                    cpuChart.data.datasets[0].data = values;
                    cpuChart.update('none');
                }
                
                if (history.memory && memoryChart) {
                    const times = history.memory.slice(-20).map(h => 
                        new Date(h.time).toLocaleTimeString().substring(0, 5));
                    const values = history.memory.slice(-20).map(h => h.value);
                    
                    memoryChart.data.labels = times;
                    memoryChart.data.datasets[0].data = values;
                    memoryChart.update('none');
                }
            } catch (error) {
                console.error('Error updating charts:', error);
            }
        }
        
        // Check for alerts
        async function checkAlerts(data) {
            try {
                const response = await fetch('/api/system/alerts');
                const alertsData = await response.json();
                showAlerts(alertsData.alerts);
            } catch (error) {
                // Check locally
                const alerts = [];
                if (data.cpu > 90) {
                    alerts.push({ level: 'CRITICAL', message: `CPU usage critical: ${data.cpu}%` });
                } else if (data.cpu > 80) {
                    alerts.push({ level: 'WARNING', message: `CPU usage high: ${data.cpu}%` });
                }
                
                if (data.memory > 90) {
                    alerts.push({ level: 'CRITICAL', message: `Memory usage critical: ${data.memory}%` });
                } else if (data.memory > 85) {
                    alerts.push({ level: 'WARNING', message: `Memory usage high: ${data.memory}%` });
                }
                
                if (data.disk > 95) {
                    alerts.push({ level: 'CRITICAL', message: `Disk usage critical: ${data.disk}%` });
                }
                
                showAlerts(alerts);
            }
        }
        
        function showAlerts(alerts) {
            const container = document.getElementById('alert-container');
            if (!container) return;
            
            container.innerHTML = '';
            
            if (alerts && alerts.length > 0) {
                alerts.forEach(alert => {
                    const alertDiv = document.createElement('div');
                    alertDiv.className = `mb-2 p-3 rounded-lg text-white ${
                        alert.level === 'CRITICAL' ? 'alert-critical' : 'alert-warning'
                    }`;
                    alertDiv.innerHTML = `
                        <div class="flex items-center">
                            <i class="fas fa-exclamation-triangle mr-3"></i>
                            <div>
                                <strong>${alert.level}:</strong> ${alert.message}
                            </div>
                        </div>
                    `;
                    container.appendChild(alertDiv);
                });
            }
        }
        
        // Toggle auto-refresh
        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = document.getElementById('auto-refresh-btn');
            const icon = btn.querySelector('i');
            
            if (autoRefresh) {
                btn.innerHTML = '<i class="fas fa-pause mr-3"></i>Auto-Refresh: ON';
                btn.className = btn.className.replace('bg-yellow-500', 'bg-green-500').replace('hover:bg-yellow-600', 'hover:bg-green-600');
                startAutoRefresh();
            } else {
                btn.innerHTML = '<i class="fas fa-play mr-3"></i>Auto-Refresh: OFF';
                btn.className = btn.className.replace('bg-green-500', 'bg-yellow-500').replace('hover:bg-green-600', 'hover:bg-yellow-600');
                clearInterval(refreshInterval);
            }
        }
        
        function startAutoRefresh() {
            if (refreshInterval) clearInterval(refreshInterval);
            refreshInterval = setInterval(updateRealTimeMetrics, 3000);
        }
        
        function refreshMetrics() {
            updateRealTimeMetrics();
        }
        
        // Cost calculator
        function updateCost() {
            const cpu = parseFloat(document.getElementById('cpuSlider').value);
            const memory = parseFloat(document.getElementById('memorySlider').value);
            
            document.getElementById('cpuValue').textContent = cpu;
            document.getElementById('memoryValue').textContent = memory;
            
            // AWS Fargate Pricing (ap-south-1)
            const fargateCostPerVcpuHour = 0.04048;
            const fargateCostPerGbHour = 0.00445;
            
            const hourlyCost = (cpu * fargateCostPerVcpuHour) + (memory * fargateCostPerGbHour);
            const dailyCost = hourlyCost * 24;
            const monthlyCost = dailyCost * 30;
            
            document.getElementById('hourlyCost').textContent = hourlyCost.toFixed(3);
            document.getElementById('dailyCost').textContent = dailyCost.toFixed(2);
            document.getElementById('monthlyCost').textContent = monthlyCost.toFixed(2);
        }
        
        // AWS Audit Functions
        async function runAWSAudit() {
            try {
                const response = await fetch('/api/aws/audit/quick');
                const data = await response.json();
                
                document.getElementById('aws-cost').textContent = '$' + data.estimated_monthly_cost;
                document.getElementById('aws-issues').textContent = data.critical_items.length + ' issues found';
                
                // Show alert with details
                if (data.critical_items.length > 0) {
                    let message = `Found ${data.critical_items.length} AWS cost issues:\n`;
                    data.critical_items.forEach(item => {
                        message += `\n• ${item.action} (${item.count}x) - $${item.cost_per_month}/month`;
                    });
                    message += `\n\nTotal potential savings: $${data.estimated_monthly_cost}/month`;
                    alert(message);
                } else {
                    alert('✅ No AWS cost issues found!');
                }
            } catch (error) {
                console.error('AWS audit error:', error);
                alert('❌ AWS Audit failed. Please check if AWS credentials are configured.');
            }
        }
        
        async function showAWSSavings() {
            const response = await fetch('/api/aws/audit/quick');
            const data = await response.json();
            
            // Update dashboard metrics
            document.getElementById('aws-cost').textContent = '$' + data.estimated_monthly_cost;
            document.getElementById('aws-issues').textContent = data.critical_items.length + ' issues found';
        }
        
        // Initialize everything
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            updateRealTimeMetrics();
            startAutoRefresh();
            updateCost();
            
            // Update every 10 seconds
            setInterval(updateCharts, 10000);
            
            // Load AWS audit data if available
            showAWSSavings().catch(console.error);
        });
    </script>
</body>
</html>
'''

# ===== ROUTES =====
@app.route('/')
def home():
    """Main dashboard with REAL metrics"""
    visitor_count = increment_visitor_counter()
    metrics = monitor.get_metrics()
    
    return render_template_string(
        HTML_TEMPLATE,
        hostname=socket.gethostname(),
        python_version=platform.python_version(),
        platform=platform.platform(),
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        visitor_count=visitor_count,
        redis_status=get_redis_status(),
        aws_region=AWS_REGION,
        metrics=metrics
    )

@app.route('/api/real-metrics')
def real_metrics():
    """API endpoint for real-time metrics"""
    metrics = monitor.get_metrics()
    metrics['redis_connected'] = REDIS_AVAILABLE
    metrics['aws_audit_available'] = AWS_AUDIT_AVAILABLE
    return jsonify(metrics)

@app.route('/api/metrics/history')
def metrics_history():
    """Historical metrics for charts"""
    return jsonify(monitor.get_history())

@app.route('/api/metrics/live')
def metrics_live():
    """Server-Sent Events stream"""
    def generate():
        while True:
            metrics = monitor.get_metrics()
            metrics['redis_connected'] = REDIS_AVAILABLE
            yield f"data: {json.dumps(metrics)}\n\n"
            time.sleep(3)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/system/alerts')
def system_alerts():
    """Get system alerts"""
    alerts = monitor.get_alerts()
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'alerts': alerts,
        'count': len(alerts),
        'thresholds': {
            'cpu': ALERT_CPU_THRESHOLD,
            'memory': ALERT_MEMORY_THRESHOLD,
            'disk': ALERT_DISK_THRESHOLD
        }
    })

@app.route('/health')
def health():
    """Enhanced health check"""
    metrics = monitor.get_metrics()
    alerts = monitor.get_alerts()
    
    status = "healthy"
    if any(alert['level'] == 'CRITICAL' for alert in alerts):
        status = "critical"
    elif len(alerts) > 0:
        status = "degraded"
    
    checks = {
        "cpu_ok": metrics['cpu'] < ALERT_CPU_THRESHOLD,
        "memory_ok": metrics['memory'] < ALERT_MEMORY_THRESHOLD,
        "disk_ok": metrics['disk'] < ALERT_DISK_THRESHOLD,
        "redis_connected": REDIS_AVAILABLE,
        "app_running": True,
        "aws_audit_available": AWS_AUDIT_AVAILABLE
    }
    
    return jsonify({
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "service": "python-web-app",
        "version": "2.3.0",
        "metrics": metrics,
        "checks": checks,
        "alerts": alerts
    })

@app.route('/info')
def info():
    """Application information"""
    metrics = monitor.get_metrics()
    return {
        "application": {
            "name": "Python Flask EKS Deployment",
            "version": "2.3.0",
            "description": "Containerized web app with real-time monitoring & AWS cost audit",
            "author": "DevOps Learning Project",
            "features": ["Real-time Metrics", "Visitor Analytics", "Cost Calculator", "EKS Deployment", "AWS Cost Audit"]
        },
        "environment": {
            "python_version": platform.python_version(),
            "flask_version": "2.3.3",
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "redis": "connected" if REDIS_AVAILABLE else "in_memory",
            "aws_audit": "available" if AWS_AUDIT_AVAILABLE else "unavailable"
        },
        "deployment": {
            "platform": "AWS EKS",
            "region": AWS_REGION,
            "containerized": True,
            "real_time_metrics": True
        },
        "metrics": metrics,
        "endpoints": [
            {"path": "/", "method": "GET", "description": "Real-time dashboard"},
            {"path": "/health", "method": "GET", "description": "Health check with metrics"},
            {"path": "/api/real-metrics", "method": "GET", "description": "Real-time metrics (JSON)"},
            {"path": "/api/metrics/live", "method": "GET", "description": "Live metrics stream (SSE)"},
            {"path": "/api/system/alerts", "method": "GET", "description": "System alerts"},
            {"path": "/api/cost", "method": "GET", "description": "AWS cost calculator"},
            {"path": "/api/aws/audit", "method": "GET", "description": "Complete AWS audit"},
            {"path": "/api/aws/audit/quick", "method": "GET", "description": "Quick AWS cost audit"},
            {"path": "/api/aws/audit/structured", "method": "GET", "description": "Structured AWS audit"}
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.route('/api/cost')
def cost_calculator():
    """AWS cost calculator API"""
    cpu = float(request.args.get('cpu', 0.25))
    memory = float(request.args.get('memory', 0.5))
    
    hourly = (cpu * FARGATE_CPU_PRICE) + (memory * FARGATE_MEMORY_PRICE)
    
    return jsonify({
        'resources': {'cpu': cpu, 'memory': memory},
        'pricing': {
            'cpu_per_hour': FARGATE_CPU_PRICE,
            'memory_per_gb_hour': FARGATE_MEMORY_PRICE,
            'region': AWS_REGION
        },
        'costs': {
            'hourly': round(hourly, 4),
            'daily': round(hourly * 24, 2),
            'monthly': round(hourly * 24 * 30, 2),
            'yearly': round(hourly * 24 * 365, 2)
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/visitors')
def visitors():
    """Get visitor statistics"""
    try:
        recent = redis_client.lrange('recent_visits', 0, 9)
        return jsonify({
            'total': redis_client.get('visitor_count') or 0,
            'recent': [json.loads(v) for v in recent] if recent else [],
            'flask_visitors': monitor.visitors,
            'flask_recent': monitor.visitor_details[:10]
        })
    except:
        return jsonify({
            'total': 0,
            'recent': [],
            'flask_visitors': monitor.visitors,
            'flask_recent': monitor.visitor_details[:10]
        })

@app.route('/metrics')
def metrics():
    """Simple metrics endpoint"""
    return jsonify(monitor.get_metrics())

@app.route('/api/status')
def api_status():
    """Lightweight status"""
    return {
        "status": "operational",
        "features": {
            "real_time_metrics": "enabled",
            "visitor_counter": "enabled",
            "cost_calculator": "enabled",
            "alerts": "enabled",
            "charts": "enabled",
            "aws_audit": "enabled" if AWS_AUDIT_AVAILABLE else "disabled"
        },
        "timestamp": datetime.now().isoformat()
    }

# ===== AWS AUDIT ROUTES =====
@app.route('/api/aws/audit')
def aws_audit_endpoint():
    """Run complete AWS audit"""
    if not AWS_AUDIT_AVAILABLE:
        return jsonify({
            "error": "AWS Audit module not available",
            "message": "Please install the AWS audit module or check configuration"
        }), 503
    
    try:
        result = aws_audit.run_audit()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "AWS audit failed",
            "message": str(e)
        }), 500

@app.route('/api/aws/audit/structured')
def aws_audit_structured():
    """Get structured AWS audit (Python-native)"""
    if not AWS_AUDIT_AVAILABLE:
        return jsonify({
            "error": "AWS Audit module not available",
            "message": "Please install the AWS audit module or check configuration"
        }), 503
    
    try:
        result = aws_audit.get_structured_audit()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "AWS structured audit failed",
            "message": str(e)
        }), 500

@app.route('/api/aws/audit/quick')
def aws_audit_quick():
    """Quick audit - just critical cost items"""
    if not AWS_AUDIT_AVAILABLE:
        return jsonify({
            "error": "AWS Audit module not available",
            "message": "Please install the AWS audit module or check configuration"
        }), 503
    
    try:
        result = aws_audit.get_structured_audit()
        
        # Filter to only cost-related items
        quick_result = {
            'timestamp': datetime.now().isoformat(),
            'critical_items': [],
            'estimated_monthly_cost': 0,
            'aws_audit_available': True
        }
        
        # Calculate estimated cost
        if 'unattached_volumes' in result and 'count' in result['unattached_volumes']:
            count = result['unattached_volumes']['count']
            if count > 0:
                quick_result['critical_items'].append({
                    'type': 'unattached_ebs',
                    'count': count,
                    'cost_per_month': count * 1,  # ~$1 per volume/month
                    'action': 'Delete volumes'
                })
        
        if 'unattached_eips' in result and 'count' in result['unattached_eips']:
            count = result['unattached_eips']['count']
            if count > 0:
                quick_result['critical_items'].append({
                    'type': 'unattached_eip',
                    'count': count,
                    'cost_per_month': count * 3.6,  # ~$3.6 per EIP/month
                    'action': 'Release Elastic IPs'
                })
        
        # Sum costs
        quick_result['estimated_monthly_cost'] = sum(
            item['cost_per_month'] for item in quick_result['critical_items']
        )
        
        return jsonify(quick_result)
    except Exception as e:
        return jsonify({
            "error": "AWS quick audit failed",
            "message": str(e),
            "estimated_monthly_cost": 0,
            "critical_items": [],
            "aws_audit_available": True
        })

# ===== START THE APPLICATION =====
if __name__ == '__main__':
    print("=" * 70)
    print("🚀 FLASK APP WITH REAL-TIME METRICS & AWS AUDIT - READY FOR EKS DEPLOYMENT")
    print("=" * 70)
    print(f"✅ Environment: {FLASK_ENV}")
    print(f"✅ Redis: {get_redis_status()}")
    print(f"✅ Real-time monitoring: Every {METRICS_INTERVAL}s")
    print(f"✅ Alert thresholds: CPU={ALERT_CPU_THRESHOLD}%, MEM={ALERT_MEMORY_THRESHOLD}%, DISK={ALERT_DISK_THRESHOLD}%")
    print(f"✅ AWS Region: {AWS_REGION}")
    print(f"✅ AWS Audit: {'Available' if AWS_AUDIT_AVAILABLE else 'Not Available'}")
    print("🌐 Dashboard: http://localhost:5000")
    print("📊 Live Metrics: http://localhost:5000/api/real-metrics")
    print("📈 Live Stream: http://localhost:5000/api/metrics/live")
    print("⚡ Health: http://localhost:5000/health")
    print("💰 Cost API: http://localhost:5000/api/cost?cpu=0.5&memory=1")
    print("🔍 AWS Audit: http://localhost:5000/api/aws/audit/quick")
    print("=" * 70)
    
    # Start Flask server
    app.run(
        host='0.0.0.0', 
        port=5000, 
        debug=(FLASK_ENV == 'development'),
        threaded=True
    )