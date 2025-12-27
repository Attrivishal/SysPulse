import psutil
import platform
from datetime import datetime, timedelta
import time
import threading
from collections import deque
import socket
import os

class RealTimeMonitor:
    def __init__(self, metrics_interval=5, alert_thresholds=None):
        self.metrics_interval = metrics_interval
        self.alert_thresholds = alert_thresholds or {
            'cpu': 80,
            'memory': 85,
            'disk': 90
        }
        
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
                
                time.sleep(self.metrics_interval)
        
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
                'alert_thresholds': self.alert_thresholds
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
        
        if metrics['cpu'] > self.alert_thresholds['cpu']:
            alerts.append({
                'level': 'WARNING' if metrics['cpu'] < 90 else 'CRITICAL',
                'message': f'High CPU usage: {metrics["cpu"]}%',
                'metric': 'cpu',
                'value': metrics['cpu'],
                'threshold': self.alert_thresholds['cpu']
            })
        
        if metrics['memory'] > self.alert_thresholds['memory']:
            alerts.append({
                'level': 'WARNING' if metrics['memory'] < 95 else 'CRITICAL',
                'message': f'High Memory usage: {metrics["memory"]}%',
                'metric': 'memory',
                'value': metrics['memory'],
                'threshold': self.alert_thresholds['memory']
            })
        
        if metrics['disk'] > self.alert_thresholds['disk']:
            alerts.append({
                'level': 'CRITICAL',
                'message': f'High Disk usage: {metrics["disk"]}%',
                'metric': 'disk',
                'value': metrics['disk'],
                'threshold': self.alert_thresholds['disk']
            })
        
        return alerts