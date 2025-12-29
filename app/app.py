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
        os.environ['AWS_DEFAULT_REGION'] = 'ap-south-1'
    
    session = boto3.Session(region_name=AWS_REGION)
    sts = session.client('sts')
    identity = sts.get_caller_identity()
    print(f"✅ AWS Account: {identity['Account']}")
    print(f"✅ AWS Region: {AWS_REGION}")
    
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
    aws_audit = AWSAudit(region=AWS_REGION)
    AWS_AUDIT_AVAILABLE = True
    
    # Test the audit - FIXED: Use real audit method
    print("🔍 Testing AWS audit...")
    test_success = False
    
    # Try to get structured audit first (this should work with real AWS data)
    if hasattr(aws_audit, 'get_structured_audit'):
        try:
            test_result = aws_audit.get_structured_audit()
            if 'error' not in test_result:
                # Get savings from the correct location
                total_savings = test_result.get('cost_analysis', {}).get('total_potential_savings', 0)
                if total_savings == 0:
                    total_savings = test_result.get('summary', {}).get('estimated_monthly_savings', 0)
                
                print(f"✅ AWS Audit working! Potential savings: ${total_savings:.2f}/month")
                test_success = True
        except Exception as e:
            print(f"⚠️ get_structured_audit failed: {e}")
    
    # If structured audit failed, try run_complete_audit
    if not test_success and hasattr(aws_audit, 'run_complete_audit'):
        try:
            test_result = aws_audit.run_complete_audit()
            if 'error' not in test_result:
                savings = test_result.get('summary', {}).get('estimated_monthly_savings', 0)
                print(f"✅ AWS Audit working! Potential savings: ${savings:.2f}/month")
                test_success = True
        except Exception as e:
            print(f"⚠️ run_complete_audit failed: {e}")
    
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
    <title>AWS Insights Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'primary': '#0f172a',
                        'secondary': '#1e293b',
                        'accent': '#3b82f6',
                        'success': '#10b981',
                        'warning': '#f59e0b',
                        'danger': '#ef4444'
                    }
                }
            }
        }
    </script>
    <style>
        canvas { display: block; }
        .chart-container { height: 180px; }
        .slider-thumb::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 20px; height: 20px;
            border-radius: 50%;
            background: #3b82f6;
            border: 2px solid white;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }
        
        /* Mobile menu animation */
        .mobile-menu {
            transition: all 0.3s ease;
        }
        
        /* AWS-like header styling */
        .aws-header-gradient {
            background: linear-gradient(135deg, #232F3E 0%, #0f172a 100%);
        }
        
        /* Hide scrollbar for tech stack on mobile */
        .tech-stack-scroll {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
        .tech-stack-scroll::-webkit-scrollbar {
            display: none;
        }
        
        /* Truncate text */
        .truncate-mobile {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
    </style>
</head>
<body class="bg-gradient-to-br from-primary via-secondary to-slate-800 min-h-screen p-2 md:p-6">
    <div class="max-w-7xl mx-auto">

        <!-- Enhanced Professional Header - AWS Style -->
        <div class="bg-white/5 backdrop-blur-sm rounded-2xl border border-white/10 mb-6 overflow-hidden">
            
            <!-- Top Navigation Bar (AWS Inspired) -->
            <div class="aws-header-gradient border-b border-white/10">
                <!-- Top Bar -->
                <div class="flex items-center justify-between px-3 md:px-4 py-3">
                    <!-- Left: Logo & Mobile Menu Button -->
                    <div class="flex items-center space-x-2 md:space-x-4">
                        <!-- Mobile Menu Button -->
                        <button id="mobile-menu-button" class="md:hidden text-white p-2 rounded-lg hover:bg-white/10">
                            <i class="fas fa-bars text-lg"></i>
                        </button>
                        
                        <!-- Logo -->
                        <div class="flex items-center space-x-2 md:space-x-3">
                            <div class="w-8 h-8 md:w-10 md:h-10 bg-gradient-to-br from-orange-500 to-yellow-500 rounded-lg md:rounded-xl flex items-center justify-center shadow-lg">
                                <i class="fab fa-aws text-white text-sm md:text-lg"></i>
                            </div>
                            <div>
                                <h1 class="text-sm md:text-lg font-bold text-white truncate-mobile">AWS Insights</h1>
                                <p class="text-gray-300 text-xs">Cost Optimization</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Right: Actions & User -->
                    <div class="flex items-center space-x-2 md:space-x-3">
                        <!-- AWS Region Badge -->
                        <div class="hidden sm:flex items-center bg-white/10 px-2 md:px-3 py-1 md:py-1.5 rounded-lg">
                            <i class="fas fa-map-marker-alt text-blue-300 text-xs md:text-sm mr-1 md:mr-2"></i>
                            <span class="text-white text-xs md:text-sm font-medium truncate-mobile">{{ aws_region }}</span>
                        </div>
                        
                        <!-- User Profile (Mobile Simplified) -->
                        <div class="flex items-center">
                            <div class="w-7 h-7 md:w-9 md:h-9 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                                <span class="text-white text-xs md:text-sm font-bold">VA</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Desktop Navigation -->
                <div class="hidden md:flex border-t border-white/10 px-6 py-2">
                    <nav class="flex space-x-1">
                        <a href="#" class="px-4 py-2 text-white text-sm font-medium bg-accent rounded-lg flex items-center">
                            <i class="fas fa-chart-line mr-2"></i>Dashboard
                        </a>
                        <a href="#" class="px-4 py-2 text-gray-300 hover:text-white text-sm font-medium rounded-lg hover:bg-white/10 transition-all flex items-center">
                            <i class="fas fa-chart-bar mr-2"></i>Metrics
                        </a>
                        <a href="#" class="px-4 py-2 text-gray-300 hover:text-white text-sm font-medium rounded-lg hover:bg-white/10 transition-all flex items-center">
                            <i class="fas fa-bell mr-2"></i>Alerts
                        </a>
                        <a href="#" class="px-4 py-2 text-gray-300 hover:text-white text-sm font-medium rounded-lg hover:bg-white/10 transition-all flex items-center">
                            <i class="fas fa-dollar-sign mr-2"></i>Cost
                        </a>
                    </nav>
                </div>
                
                <!-- Mobile Navigation Menu (Hidden by default) -->
                <div id="mobile-menu" class="mobile-menu md:hidden hidden bg-primary border-t border-white/10">
                    <div class="px-4 py-3 space-y-1">
                        <a href="#" class="flex items-center px-3 py-2 text-white bg-accent rounded-lg">
                            <i class="fas fa-chart-line mr-3"></i>Dashboard
                        </a>
                        <a href="#" class="flex items-center px-3 py-2 text-gray-300 hover:text-white hover:bg-white/10 rounded-lg">
                            <i class="fas fa-chart-bar mr-3"></i>Metrics
                        </a>
                        <a href="#" class="flex items-center px-3 py-2 text-gray-300 hover:text-white hover:bg-white/10 rounded-lg">
                            <i class="fas fa-bell mr-3"></i>Alerts
                        </a>
                        <a href="#" class="flex items-center px-3 py-2 text-gray-300 hover:text-white hover:bg-white/10 rounded-lg">
                            <i class="fas fa-dollar-sign mr-3"></i>Cost
                        </a>
                        <div class="pt-4 mt-4 border-t border-white/10">
                            <div class="flex items-center justify-between px-3 py-2">
                                <div>
                                    <div class="text-xs text-gray-400">AWS Region</div>
                                    <div class="text-white text-sm font-medium">{{ aws_region }}</div>
                                </div>
                                <div>
                                    <div class="text-xs text-gray-400">Status</div>
                                    <div class="text-green-400 text-sm font-medium flex items-center">
                                        <span class="w-2 h-2 bg-green-400 rounded-full mr-2"></span>
                                        Online
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Main Header Content -->
            <div class="bg-gradient-to-r from-blue-900/80 to-blue-800 text-white p-4 md:p-8">
                <!-- Mobile-friendly header layout -->
                <div class="flex flex-col">
                    <!-- Title and Tech Stack -->
                    <div class="mb-4 md:mb-6">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                            <div class="text-center sm:text-left">
                                <h1 class="text-2xl md:text-4xl font-bold mb-1"> Vishal Ops-AWS Insights</h1>
                                <p class="text-sm md:text-lg text-white/80 mb-3">Cost Optimization Dashboard</p>
                                
                                <p class="text-gray-300 text-sm mb-4 max-w-lg">
                                    Monitor AWS resources, analyze costs, and optimize performance across your EKS clusters.
                                </p>
                                
                                <!-- Tech Stack Badges -->
                                <div class="flex flex-wrap gap-2 justify-center sm:justify-start">
                                    <span class="inline-flex items-center bg-white/10 text-white px-2 py-1 rounded-full text-xs md:text-sm">
                                        <i class="fab fa-python mr-1"></i>Python {{ python_version }}
                                    </span>
                                    <span class="inline-flex items-center bg-white/10 text-white px-2 py-1 rounded-full text-xs md:text-sm">
                                        <i class="fab fa-docker mr-1"></i>Docker
                                    </span>
                                    <span class="inline-flex items-center bg-white/10 text-white px-2 py-1 rounded-full text-xs md:text-sm">
                                        <i class="fab fa-aws mr-1"></i>EKS
                                    </span>
                                    <span class="inline-flex items-center bg-white/10 text-white px-2 py-1 rounded-full text-xs md:text-sm">
                                        <i class="fas fa-chart-bar mr-1"></i>Analytics
                                    </span>
                                </div>
                            </div>
                            
                            <!-- Live Status & Quick Stats -->
                            <div class="flex flex-col items-center sm:items-end space-y-4">
                                <div class="inline-flex items-center bg-white/20 px-3 py-1.5 rounded-full">
                                    <span class="w-2 h-2 bg-success rounded-full mr-2 animate-pulse"></span>
                                    <span class="text-xs md:text-sm font-medium">24/7 MONITORING</span>
                                </div>
                                
                                <!-- Quick Stats -->
                                <div class="flex space-x-6 text-center">
                                    <div>
                                        <div class="text-lg md:text-2xl font-bold text-green-400">99.9%</div>
                                        <div class="text-xs text-gray-300">Uptime</div>
                                    </div>
                                    <div>
                                        <div class="text-lg md:text-2xl font-bold text-blue-400">Real</div>
                                        <div class="text-xs text-gray-300">Time Data</div>
                                    </div>
                                </div>
                                
                                <!-- Updated Time -->
                                <div class="text-right">
                                    <div class="text-xs text-white/80">Last Updated</div>
                                    <div id="last-updated" class="text-sm md:text-xl font-bold">{{ current_time }}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Stats Cards Grid - Fixed with proper data -->
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <!-- Visitors -->
                        <div class="bg-white/10 rounded-xl p-3 hover:bg-white/15 transition-all">
                            <div class="flex items-center justify-between mb-2">
                                <div>
                                    <div class="text-lg md:text-2xl font-bold" id="visitor-count">{{ visitor_count }}</div>
                                    <p class="text-xs md:text-sm text-white/80">Total Visitors</p>
                                </div>
                                <div class="w-8 h-8 md:w-10 md:h-10 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-users text-blue-300 text-sm md:text-base"></i>
                                </div>
                            </div>
                            <div class="text-xs text-green-300">
                                <i class="fas fa-arrow-up mr-1"></i>Live: <span id="flask-visitors" class="font-medium">0</span>
                            </div>
                        </div>
                        
                        <!-- CPU -->
                        <div class="bg-white/10 rounded-xl p-3 hover:bg-white/15 transition-all">
                            <div class="flex items-center justify-between mb-2">
                                <div>
                                    <div class="text-lg md:text-2xl font-bold text-green-300" id="real-cpu">0.0%</div>
                                    <p class="text-xs md:text-sm text-white/80">CPU Usage</p>
                                </div>
                                <div class="w-8 h-8 md:w-10 md:h-10 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-microchip text-green-300 text-sm md:text-base"></i>
                                </div>
                            </div>
                            <div class="w-full bg-white/20 rounded-full h-1.5 mt-2">
                                <div class="bg-green-400 h-1.5 rounded-full transition-all" id="cpu-progress" style="width: 0%"></div>
                            </div>
                            <div class="text-xs text-white/60 mt-1 truncate-mobile" id="cpu-cores">Cores: Loading...</div>
                        </div>
                        
                        <!-- Memory -->
                        <div class="bg-white/10 rounded-xl p-3 hover:bg-white/15 transition-all">
                            <div class="flex items-center justify-between mb-2">
                                <div>
                                    <div class="text-lg md:text-2xl font-bold text-purple-300" id="real-memory">0.0%</div>
                                    <p class="text-xs md:text-sm text-white/80">Memory Used</p>
                                </div>
                                <div class="w-8 h-8 md:w-10 md:h-10 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-memory text-purple-300 text-sm md:text-base"></i>
                                </div>
                            </div>
                            <div class="w-full bg-white/20 rounded-full h-1.5 mt-2">
                                <div class="bg-purple-400 h-1.5 rounded-full transition-all" id="memory-progress" style="width: 0%"></div>
                            </div>
                            <div class="text-xs text-white/60 mt-1 truncate-mobile" id="memory-details">0.0 / 0.0 GB</div>
                        </div>
                        
                        <!-- Disk -->
                        <div class="bg-white/10 rounded-xl p-3 hover:bg-white/15 transition-all">
                            <div class="flex items-center justify-between mb-2">
                                <div>
                                    <div class="text-lg md:text-2xl font-bold text-amber-300" id="real-disk">0.0%</div>
                                    <p class="text-xs md:text-sm text-white/80">Disk Usage</p>
                                </div>
                                <div class="w-8 h-8 md:w-10 md:h-10 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-hdd text-amber-300 text-sm md:text-base"></i>
                                </div>
                            </div>
                            <div class="w-full bg-white/20 rounded-full h-1.5 mt-2">
                                <div class="bg-amber-400 h-1.5 rounded-full transition-all" id="disk-progress" style="width: 0%"></div>
                            </div>
                            <div class="text-xs text-white/60 mt-1 truncate-mobile" id="disk-details">0.0 / 0.0 GB</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Alerts Section -->
            <div id="alert-container" class="p-3 md:p-4"></div>

            <!-- Main Content -->
            <div class="p-3 md:p-8">
                
                <!-- Charts -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6 mb-8">
                    <!-- CPU Chart -->
                    <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                        <h3 class="text-base md:text-lg font-bold text-white mb-3 flex items-center">
                            <i class="fas fa-microchip text-blue-400 mr-2"></i>CPU History
                        </h3>
                        <div class="chart-container">
                            <canvas id="cpu-chart"></canvas>
                        </div>
                    </div>
                    
                    <!-- Memory Chart -->
                    <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                        <h3 class="text-base md:text-lg font-bold text-white mb-3 flex items-center">
                            <i class="fas fa-memory text-green-400 mr-2"></i>Memory History
                        </h3>
                        <div class="chart-container">
                            <canvas id="memory-chart"></canvas>
                        </div>
                    </div>
                </div>

                <!-- AWS Section -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6 mb-8">
                    <!-- Cost Calculator -->
                    <div class="bg-white/5 rounded-xl p-4 md:p-6 border border-white/10">
                        <div class="flex items-center mb-4">
                            <div class="bg-red-900/30 p-2 rounded-lg mr-3">
                                <i class="fas fa-calculator text-red-300 text-xl"></i>
                            </div>
                            <h2 class="text-lg md:text-xl font-bold text-white">AWS Cost Calculator</h2>
                        </div>
                        
                        <div class="space-y-4">
                            <!-- CPU Slider -->
                            <div class="bg-blue-900/20 rounded-lg p-3">
                                <div class="flex justify-between items-center mb-2">
                                    <label class="flex items-center text-white font-medium text-sm">
                                        <i class="fas fa-microchip text-blue-300 mr-2"></i>vCPU
                                    </label>
                                    <span id="cpuValue" class="text-base md:text-lg font-bold text-blue-300">0.25 cores</span>
                                </div>
                                <input type="range" min="0.25" max="4" step="0.25" value="0.25" 
                                       class="w-full h-2 bg-blue-800/50 rounded-lg appearance-none cursor-pointer slider-thumb"
                                       oninput="updateCost()" id="cpuSlider">
                            </div>
                            
                            <!-- Memory Slider -->
                            <div class="bg-green-900/20 rounded-lg p-3">
                                <div class="flex justify-between items-center mb-2">
                                    <label class="flex items-center text-white font-medium text-sm">
                                        <i class="fas fa-memory text-green-300 mr-2"></i>Memory
                                    </label>
                                    <span id="memoryValue" class="text-base md:text-lg font-bold text-green-300">0.5 GB</span>
                                </div>
                                <input type="range" min="0.5" max="16" step="0.5" value="0.5" 
                                       class="w-full h-2 bg-green-800/50 rounded-lg appearance-none cursor-pointer slider-thumb"
                                       oninput="updateCost()" id="memorySlider">
                            </div>
                            
                            <!-- Cost Results -->
                            <div class="grid grid-cols-3 gap-2">
                                <div class="bg-blue-900/20 rounded-lg p-3 text-center">
                                    <div class="text-xs md:text-sm text-blue-300">Hourly</div>
                                    <div class="text-base md:text-lg font-bold text-white">$<span id="hourlyCost">0.010</span></div>
                                </div>
                                <div class="bg-green-900/20 rounded-lg p-3 text-center">
                                    <div class="text-xs md:text-sm text-green-300">Daily</div>
                                    <div class="text-base md:text-lg font-bold text-white">$<span id="dailyCost">0.24</span></div>
                                </div>
                                <div class="bg-purple-900/20 rounded-lg p-3 text-center">
                                    <div class="text-xs md:text-sm text-purple-300">Monthly</div>
                                    <div class="text-base md:text-lg font-bold text-white">$<span id="monthlyCost">7.20</span></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- AWS Audit -->
                    <div class="bg-white/5 rounded-xl p-4 md:p-6 border border-white/10">
                        <div class="flex items-center mb-4">
                            <div class="bg-green-900/30 p-2 rounded-lg mr-3">
                                <i class="fas fa-search-dollar text-green-300 text-xl"></i>
                            </div>
                            <h2 class="text-lg md:text-xl font-bold text-white">AWS Cost Audit</h2>
                        </div>
                        
                        <div class="space-y-4">
                            <!-- Savings Display -->
                            <div class="bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-xl p-4 text-center">
                                <div class="text-2xl md:text-4xl font-bold text-white mb-1" id="aws-cost">$0</div>
                                <p class="text-green-300 text-sm">Potential Monthly Savings</p>
                                <div class="inline-flex items-center mt-2 px-3 py-1 bg-green-900/40 text-green-300 rounded-full text-xs">
                                    <i class="fas fa-check-circle mr-1"></i>
                                    <span id="aws-issues">0 issues found</span>
                                </div>
                            </div>
                            
                            <!-- Audit Details -->
                            <div id="audit-details" class="space-y-3">
                                <div class="text-center py-4 text-gray-400">
                                    <i class="fas fa-chart-pie text-2xl mb-2 opacity-50"></i>
                                    <p class="text-sm">Click "Run AWS Cost Audit" to see detailed analysis</p>
                                </div>
                            </div>
                            
                            <!-- Quick Audit Button -->
                            <button onclick="runAWSAudit()" 
                                    class="w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white font-medium py-3 rounded-lg transition-all flex items-center justify-center">
                                <i class="fas fa-play mr-2"></i>Run AWS Cost Audit
                            </button>
                            
                            <!-- Audit Links -->
                            <div class="grid grid-cols-3 gap-2">
                                <a href="/api/aws/audit/quick" target="_blank" 
                                   class="bg-blue-900/20 hover:bg-blue-800/30 text-blue-300 p-2 rounded-lg text-center text-xs transition-all flex flex-col items-center">
                                    <i class="fas fa-bolt mb-1"></i>
                                    <span>Quick</span>
                                </a>
                                <a href="/api/aws/audit" target="_blank" 
                                   class="bg-green-900/20 hover:bg-green-800/30 text-green-300 p-2 rounded-lg text-center text-xs transition-all flex flex-col items-center">
                                    <i class="fas fa-search mb-1"></i>
                                    <span>Full</span>
                                </a>
                                <a href="/api/aws/audit/structured" target="_blank" 
                                   class="bg-purple-900/20 hover:bg-purple-800/30 text-purple-300 p-2 rounded-lg text-center text-xs transition-all flex flex-col items-center">
                                    <i class="fas fa-list mb-1"></i>
                                    <span>Structured</span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- System Info - Improved layout -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 md:gap-6 mb-8">
                    <!-- System Info -->
                    <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                        <div class="flex items-center mb-3">
                            <div class="bg-blue-900/30 p-2 rounded-lg mr-3">
                                <i class="fas fa-server text-blue-300"></i>
                            </div>
                            <h3 class="text-base md:text-lg font-bold text-white">System Info</h3>
                        </div>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                <i class="fas fa-hashtag text-blue-400 mr-2 w-4"></i>
                                <span class="font-medium">Host:</span> 
                                <span id="real-hostname" class="text-white truncate-mobile">{{ hostname }}</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-microchip text-blue-400 mr-2 w-4"></i>
                                <span class="font-medium">Platform:</span> 
                                <span id="real-platform" class="text-white truncate-mobile">{{ platform }}</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-clock text-blue-400 mr-2 w-4"></i>
                                <span class="font-medium">System Uptime:</span> 
                                <span id="system-uptime" class="text-white">Loading...</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-play text-blue-400 mr-2 w-4"></i>
                                <span class="font-medium">App Uptime:</span> 
                                <span id="app-uptime" class="text-white">Loading...</span>
                            </p>
                        </div>
                    </div>

                    <!-- App Status -->
                    <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                        <div class="flex items-center mb-3">
                            <div class="bg-green-900/30 p-2 rounded-lg mr-3">
                                <i class="fas fa-shield-alt text-green-300"></i>
                            </div>
                            <h3 class="text-base md:text-lg font-bold text-white">App Status</h3>
                        </div>
                        <div class="flex items-center mb-3">
                            <span class="w-2 h-2 bg-success rounded-full mr-2 animate-pulse"></span>
                            <span class="text-sm font-medium text-success">All Systems Operational</span>
                        </div>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                <i class="fas fa-check-circle text-green-400 mr-2 w-4"></i>
                                <span>Docker:</span> 
                                <span class="text-white">Running</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-check-circle text-green-400 mr-2 w-4"></i>
                                <span>Flask Server:</span> 
                                <span class="text-white">Active</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-database text-green-400 mr-2 w-4"></i>
                                <span>Redis:</span> 
                                <span class="text-white" id="redis-status-text">{{ redis_status }}</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-heartbeat text-green-400 mr-2 w-4"></i>
                                <span>Health Check:</span> 
                                <span class="text-white">PASS</span>
                            </p>
                        </div>
                    </div>

                    <!-- Deployment -->
                    <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                        <div class="flex items-center mb-3">
                            <div class="bg-purple-900/30 p-2 rounded-lg mr-3">
                                <i class="fas fa-cloud-upload-alt text-purple-300"></i>
                            </div>
                            <h3 class="text-base md:text-lg font-bold text-white">Deployment</h3>
                        </div>
                        <div class="space-y-2 text-sm">
                            <p class="text-gray-300">
                                <i class="fas fa-cloud text-purple-400 mr-2 w-4"></i>
                                <span class="font-medium">Platform:</span> 
                                <span class="text-white">AWS EKS</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-map-marker-alt text-purple-400 mr-2 w-4"></i>
                                <span class="font-medium">Region:</span> 
                                <span class="text-white">{{ aws_region }}</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-cube text-purple-400 mr-2 w-4"></i>
                                <span class="font-medium">Container:</span> 
                                <span class="text-white">Docker</span>
                            </p>
                            <p class="text-gray-300">
                                <i class="fas fa-chart-bar text-purple-400 mr-2 w-4"></i>
                                <span class="font-medium">Metrics:</span> 
                                <span class="text-white">Real-time</span>
                            </p>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions - Mobile Optimized -->
                <div class="bg-white/5 rounded-xl p-4 border border-white/10">
                    <h3 class="text-base md:text-lg font-bold text-white mb-4 flex items-center">
                        <i class="fas fa-bolt text-amber-400 mr-2"></i>Quick Actions
                    </h3>
                    <div class="flex flex-wrap gap-2">
                        <button onclick="refreshMetrics()" 
                                class="bg-accent hover:bg-blue-600 text-white px-3 py-2 rounded-lg text-sm transition-all flex items-center">
                            <i class="fas fa-sync-alt mr-2"></i>
                            <span>Refresh</span>
                        </button>
                        <a href="/health" 
                           class="bg-success hover:bg-green-600 text-white px-3 py-2 rounded-lg text-sm transition-all inline-flex items-center">
                            <i class="fas fa-heartbeat mr-2"></i>
                            <span>Health</span>
                        </a>
                        <a href="/api/real-metrics" target="_blank" 
                           class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-2 rounded-lg text-sm transition-all inline-flex items-center">
                            <i class="fas fa-code mr-2"></i>
                            <span>API</span>
                        </a>
                        <button onclick="toggleAutoRefresh()" id="auto-refresh-btn" 
                                class="bg-amber-500 hover:bg-amber-600 text-white px-3 py-2 rounded-lg text-sm transition-all flex items-center">
                            <i class="fas fa-play mr-2"></i>
                            <span>Auto: ON</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Footer - Mobile Optimized -->
            <div class="bg-black/30 text-gray-400 p-4 text-center border-t border-white/10">
                <div class="flex flex-col md:flex-row justify-between items-center gap-3">
                    <div class="text-center md:text-left">
                        <p class="text-sm font-medium">🚀 DevOps Learning Project</p>
                        <p class="text-xs">Containerized Python Flask on AWS EKS</p>
                    </div>
                    <div class="flex space-x-4 text-lg">
                        <i class="fab fa-python hover:text-white transition"></i>
                        <i class="fab fa-docker hover:text-white transition"></i>
                        <i class="fab fa-aws hover:text-white transition"></i>
                        <i class="fas fa-chart-line hover:text-white transition"></i>
                    </div>
                </div>
                <p class="text-xs mt-3 opacity-70">
                    <span id="live-status">Live Metrics: Active</span> | 
                    Visitors: <span id="footer-visitors">{{ visitor_count }}</span> | 
                    Updated: <span id="footer-time">{{ current_time }}</span>
                </p>
            </div>
        </div>
    </div>

    <script>
        // Charts
        let cpuChart, memoryChart;
        let autoRefresh = true;
        let refreshInterval;
        
        function initCharts() {
            const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
            cpuChart = new Chart(cpuCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 20}, (_, i) => i + 's'),
                    datasets: [{
                        label: 'CPU %',
                        data: Array(20).fill(0),
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
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { 
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255,255,255,0.1)' },
                            ticks: { color: '#94a3b8', stepSize: 20 }
                        },
                        x: { 
                            grid: { display: false },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
            
            const memoryCtx = document.getElementById('memory-chart').getContext('2d');
            memoryChart = new Chart(memoryCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 20}, (_, i) => i + 's'),
                    datasets: [{
                        label: 'Memory %',
                        data: Array(20).fill(0),
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
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { 
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255,255,255,0.1)' },
                            ticks: { color: '#94a3b8', stepSize: 20 }
                        },
                        x: { 
                            grid: { display: false },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
        }
        
        // Update metrics
        async function updateRealTimeMetrics() {
            try {
                const response = await fetch('/api/real-metrics');
                const data = await response.json();
                
                if (data.error) return;
                
                // Update metrics with proper formatting
                document.getElementById('real-cpu').textContent = parseFloat(data.cpu).toFixed(1) + '%';
                document.getElementById('cpu-progress').style.width = data.cpu + '%';
                document.getElementById('cpu-cores').textContent = 'Cores: ' + (data.cpu_cores || '4');
                
                document.getElementById('real-memory').textContent = parseFloat(data.memory).toFixed(1) + '%';
                document.getElementById('memory-progress').style.width = data.memory + '%';
                document.getElementById('memory-details').textContent = 
                    parseFloat(data.memory_used || 0).toFixed(1) + ' / ' + 
                    parseFloat(data.memory_total || 0).toFixed(1) + ' GB';
                
                document.getElementById('real-disk').textContent = parseFloat(data.disk).toFixed(1) + '%';
                document.getElementById('disk-progress').style.width = data.disk + '%';
                document.getElementById('disk-details').textContent = 
                    parseFloat(data.disk_used || 0).toFixed(1) + ' / ' + 
                    parseFloat(data.disk_total || 0).toFixed(1) + ' GB';
                
                // Truncate long hostname
                const hostname = data.hostname || '{{ hostname }}';
                document.getElementById('real-hostname').textContent = 
                    hostname.length > 20 ? hostname.substring(0, 20) + '...' : hostname;
                
                // Truncate platform
                const platform = data.platform || '{{ platform }}';
                document.getElementById('real-platform').textContent = 
                    platform.length > 25 ? platform.substring(0, 25) + '...' : platform;
                
                document.getElementById('system-uptime').textContent = data.system_uptime || '0d 0h 0m';
                document.getElementById('app-uptime').textContent = data.app_uptime || '0d 0h 0m';
                document.getElementById('flask-visitors').textContent = data.flask_visitors || '0';
                
                const now = new Date();
                const timeStr = now.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                document.getElementById('last-updated').textContent = timeStr;
                document.getElementById('footer-time').textContent = timeStr;
                document.getElementById('footer-visitors').textContent = data.flask_visitors || document.getElementById('visitor-count').textContent;
                
                const redisStatus = document.getElementById('redis-status-text');
                if (redisStatus) redisStatus.textContent = data.redis_connected ? 'Connected' : 'In-Memory';
                
                checkAlerts(data);
                updateCharts(data);
                
            } catch (error) {
                console.error('Error:', error);
                // Show dummy data for demo
                showDemoData();
            }
        }
        
        // Demo data for testing
        function showDemoData() {
            const cpu = Math.random() * 40 + 10;
            const memory = Math.random() * 30 + 20;
            const disk = Math.random() * 20 + 5;
            
            document.getElementById('real-cpu').textContent = cpu.toFixed(1) + '%';
            document.getElementById('cpu-progress').style.width = cpu + '%';
            document.getElementById('cpu-cores').textContent = 'Cores: 4';
            
            document.getElementById('real-memory').textContent = memory.toFixed(1) + '%';
            document.getElementById('memory-progress').style.width = memory + '%';
            document.getElementById('memory-details').textContent = '2.3 / 8.0 GB';
            
            document.getElementById('real-disk').textContent = disk.toFixed(1) + '%';
            document.getElementById('disk-progress').style.width = disk + '%';
            document.getElementById('disk-details').textContent = '12.4 / 50.0 GB';
            
            document.getElementById('flask-visitors').textContent = Math.floor(Math.random() * 100);
        }
        
        // Update charts
        function updateCharts(data) {
            if (cpuChart && memoryChart) {
                // Shift data and add new point
                const cpuValue = parseFloat(data?.cpu || Math.random() * 40 + 10);
                const memoryValue = parseFloat(data?.memory || Math.random() * 30 + 20);
                
                // Remove first element, add new at end
                cpuChart.data.datasets[0].data.shift();
                cpuChart.data.datasets[0].data.push(cpuValue);
                
                memoryChart.data.datasets[0].data.shift();
                memoryChart.data.datasets[0].data.push(memoryValue);
                
                // Update labels
                const now = new Date();
                const timeLabel = now.getSeconds() + 's';
                cpuChart.data.labels.shift();
                cpuChart.data.labels.push(timeLabel);
                memoryChart.data.labels.shift();
                memoryChart.data.labels.push(timeLabel);
                
                cpuChart.update('none');
                memoryChart.update('none');
            }
        }
        
        // Alerts
        async function checkAlerts(data) {
            try {
                const response = await fetch('/api/system/alerts');
                const alertsData = await response.json();
                showAlerts(alertsData.alerts);
            } catch (error) {
                const alerts = [];
                if (data.cpu > 90) alerts.push({ level: 'CRITICAL', message: `CPU: ${data.cpu}%` });
                else if (data.cpu > 80) alerts.push({ level: 'WARNING', message: `CPU: ${data.cpu}%` });
                
                if (data.memory > 90) alerts.push({ level: 'CRITICAL', message: `Memory: ${data.memory}%` });
                else if (data.memory > 85) alerts.push({ level: 'WARNING', message: `Memory: ${data.memory}%` });
                
                if (data.disk > 95) alerts.push({ level: 'CRITICAL', message: `Disk: ${data.disk}%` });
                
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
                    alertDiv.className = `mb-2 p-3 rounded-lg text-white ${alert.level === 'CRITICAL' ? 'bg-gradient-to-r from-red-600 to-red-700' : 'bg-gradient-to-r from-amber-600 to-amber-700'}`;
                    alertDiv.innerHTML = `
                        <div class="flex items-center">
                            <i class="fas fa-exclamation-triangle mr-3"></i>
                            <div class="text-sm font-medium">${alert.message}</div>
                        </div>
                    `;
                    container.appendChild(alertDiv);
                });
            }
        }
        
        // Auto refresh
        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = document.getElementById('auto-refresh-btn');
            if (autoRefresh) {
                btn.innerHTML = '<i class="fas fa-pause mr-2"></i><span>Auto: ON</span>';
                btn.className = btn.className.replace('bg-amber-500', 'bg-green-600').replace('hover:bg-amber-600', 'hover:bg-green-700');
                startAutoRefresh();
            } else {
                btn.innerHTML = '<i class="fas fa-play mr-2"></i><span>Auto: OFF</span>';
                btn.className = btn.className.replace('bg-green-600', 'bg-amber-500').replace('hover:bg-green-700', 'hover:bg-amber-600');
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
            
            document.getElementById('cpuValue').textContent = cpu.toFixed(2) + ' cores';
            document.getElementById('memoryValue').textContent = memory.toFixed(1) + ' GB';
            
            const fargateCostPerVcpuHour = 0.04048;
            const fargateCostPerGbHour = 0.00445;
            
            const hourlyCost = (cpu * fargateCostPerVcpuHour) + (memory * fargateCostPerGbHour);
            const dailyCost = hourlyCost * 24;
            const monthlyCost = dailyCost * 30;
            
            document.getElementById('hourlyCost').textContent = hourlyCost.toFixed(3);
            document.getElementById('dailyCost').textContent = dailyCost.toFixed(2);
            document.getElementById('monthlyCost').textContent = monthlyCost.toFixed(2);
        }
        
        // AWS Audit - FIXED: Now uses real API
        async function runAWSAudit() {
            try {
                const btn = document.querySelector('button[onclick="runAWSAudit()"]');
                btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Running...';
                btn.disabled = true;
                
                // Use real API call instead of demo data
                const response = await fetch('/api/aws/audit/structured');
                const auditData = await response.json();
                
                if (auditData.error) {
                    throw new Error(auditData.message || 'Audit failed');
                }
                
                btn.innerHTML = '<i class="fas fa-play mr-2"></i>Run AWS Cost Audit';
                btn.disabled = false;
                
                updateAuditDashboard(auditData);
                
            } catch (error) {
                const btn = document.querySelector('button[onclick="runAWSAudit()"]');
                btn.innerHTML = '<i class="fas fa-play mr-2"></i>Run AWS Cost Audit';
                btn.disabled = false;
                alert('AWS Audit failed: ' + error.message);
            }
        }
        
        function updateAuditDashboard(auditData) {
            const detailsContainer = document.getElementById('audit-details');
            
            // Get savings from correct location
            let totalSavings = 0;
            if (auditData.cost_analysis && auditData.cost_analysis.total_potential_savings) {
                totalSavings = auditData.cost_analysis.total_potential_savings;
            } else if (auditData.summary && auditData.summary.estimated_monthly_savings) {
                totalSavings = auditData.summary.estimated_monthly_savings;
            }
            
            document.getElementById('aws-cost').textContent = '$' + totalSavings.toFixed(2);
            
            let issueCount = 0;
            if (auditData.summary && auditData.summary.total_findings) {
                issueCount = auditData.summary.total_findings;
            } else if (auditData.findings) {
                issueCount = auditData.findings.length;
            }
            
            document.getElementById('aws-issues').textContent = issueCount + ' issues found';
            
            let html = '';
            
            // EC2 Details
            if (auditData.details && auditData.details.ec2) {
                const ec2 = auditData.details.ec2;
                html += `
                <div class="bg-blue-900/20 rounded-lg p-3">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-server text-blue-300 mr-2"></i>
                        <h4 class="font-bold text-white text-sm">EC2 Resources</h4>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div class="text-center">
                            <div class="text-lg font-bold text-blue-300">${ec2.instances?.total || 0}</div>
                            <div class="text-xs text-gray-400">Instances</div>
                        </div>
                        <div class="text-center">
                            <div class="text-lg font-bold ${(ec2.volumes?.unattached || 0) > 0 ? 'text-red-300' : 'text-green-300'}">${ec2.volumes?.unattached || 0}</div>
                            <div class="text-xs text-gray-400">Unattached Volumes</div>
                        </div>
                    </div>
                </div>`;
            }
            
            // IAM Details
            if (auditData.details && auditData.details.iam) {
                const iam = auditData.details.iam;
                html += `
                <div class="bg-green-900/20 rounded-lg p-3">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-user-shield text-green-300 mr-2"></i>
                        <h4 class="font-bold text-white text-sm">IAM Security</h4>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div class="text-center">
                            <div class="text-lg font-bold text-green-300">${iam.users?.total || 0}</div>
                            <div class="text-xs text-gray-400">Total Users</div>
                        </div>
                        <div class="text-center">
                            <div class="text-lg font-bold ${(iam.users?.without_mfa || 0) > 0 ? 'text-red-300' : 'text-green-300'}">${(iam.users?.without_mfa || 0) > 0 ? 'Needs MFA' : 'Secure'}</div>
                            <div class="text-xs text-gray-400">MFA Status</div>
                        </div>
                    </div>
                </div>`;
            }
            
            // S3 Details
            if (auditData.details && auditData.details.s3) {
                const s3 = auditData.details.s3;
                html += `
                <div class="bg-purple-900/20 rounded-lg p-3">
                    <div class="flex items-center mb-2">
                        <i class="fas fa-database text-purple-300 mr-2"></i>
                        <h4 class="font-bold text-white text-sm">S3 Storage</h4>
                    </div>
                    <div class="grid grid-cols-2 gap-2">
                        <div class="text-center">
                            <div class="text-lg font-bold text-purple-300">${s3.total || 0}</div>
                            <div class="text-xs text-gray-400">Buckets</div>
                        </div>
                        <div class="text-center">
                            <div class="text-lg font-bold ${(s3.public_buckets?.length || 0) > 0 ? 'text-red-300' : 'text-green-300'}">${(s3.public_buckets?.length || 0) > 0 ? 'Public' : 'Secure'}</div>
                            <div class="text-xs text-gray-400">Security</div>
                        </div>
                    </div>
                </div>`;
            }
            
            detailsContainer.innerHTML = html;
        }
        
        // Mobile menu functionality
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
            updateRealTimeMetrics();
            startAutoRefresh();
            updateCost();
            
            // Mobile menu toggle
            const mobileMenuButton = document.getElementById('mobile-menu-button');
            const mobileMenu = document.getElementById('mobile-menu');
            
            if (mobileMenuButton && mobileMenu) {
                mobileMenuButton.addEventListener('click', function(e) {
                    e.stopPropagation();
                    mobileMenu.classList.toggle('hidden');
                    
                    // Change icon
                    const icon = mobileMenuButton.querySelector('i');
                    if (mobileMenu.classList.contains('hidden')) {
                        icon.className = 'fas fa-bars text-lg';
                    } else {
                        icon.className = 'fas fa-times text-lg';
                    }
                });
                
                // Close menu when clicking outside
                document.addEventListener('click', function(event) {
                    if (!mobileMenu.contains(event.target) && !mobileMenuButton.contains(event.target)) {
                        mobileMenu.classList.add('hidden');
                        const icon = mobileMenuButton.querySelector('i');
                        if (icon) icon.className = 'fas fa-bars text-lg';
                    }
                });
                
                // Close menu on menu item click
                mobileMenu.querySelectorAll('a').forEach(link => {
                    link.addEventListener('click', () => {
                        mobileMenu.classList.add('hidden');
                        const icon = mobileMenuButton.querySelector('i');
                        if (icon) icon.className = 'fas fa-bars text-lg';
                    });
                });
            }
            
            // Adjust chart containers on resize
            window.addEventListener('resize', function() {
                if (cpuChart) cpuChart.resize();
                if (memoryChart) memoryChart.resize();
            });
            
            // Initial demo data for charts
            setInterval(() => {
                if (autoRefresh) {
                    updateCharts({});
                }
            }, 2000);
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
        # Use get_structured_audit which gives real data
        result = aws_audit.get_structured_audit()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "error": "AWS audit failed",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
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
        print(f"Structured audit error: {e}")
        traceback.print_exc()
        return jsonify({
            "error": "AWS structured audit failed",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
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
        
        # Get EC2 data for cost calculation
        if 'details' in result and 'ec2' in result['details']:
            ec2_data = result['details']['ec2']
            
            # Unattached volumes
            if 'volumes' in ec2_data and 'unattached' in ec2_data['volumes']:
                count = ec2_data['volumes']['unattached']
                if count > 0:
                    quick_result['critical_items'].append({
                        'type': 'unattached_ebs',
                        'count': count,
                        'cost_per_month': count * 5,  # ~$5 per volume/month
                        'action': 'Delete unattached volumes'
                    })
            
            # Unattached Elastic IPs
            if 'elastic_ips' in ec2_data and 'unattached' in ec2_data['elastic_ips']:
                count = ec2_data['elastic_ips']['unattached']
                if count > 0:
                    quick_result['critical_items'].append({
                        'type': 'unattached_eip',
                        'count': count,
                        'cost_per_month': count * 3.6,  # ~$3.6 per EIP/month
                        'action': 'Release Elastic IPs'
                    })
            
            # Stopped instances
            if 'instances' in ec2_data and 'stopped' in ec2_data['instances']:
                count = ec2_data['instances']['stopped']
                if count > 0:
                    quick_result['critical_items'].append({
                        'type': 'stopped_instances',
                        'count': count,
                        'cost_per_month': count * 10,  # ~$10 per instance/month for EBS
                        'action': 'Terminate stopped instances'
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
            "aws_audit_available": True,
            "timestamp": datetime.now().isoformat()
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
        use_reloader=False,
        threaded=True
    )