// Real-time charts with Chart.js
let cpuChart, memoryChart, networkChart;

function initCharts() {
    // CPU Chart
    const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Usage %',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false
        }
    });
    
    // Memory Chart
    const memoryCtx = document.getElementById('memory-chart').getContext('2d');
    memoryChart = new Chart(memoryCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Memory Usage %',
                data: [],
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false
        }
    });
}

// Update charts with historical data
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
async function checkAlerts() {
    try {
        const response = await fetch('/api/system/alerts');
        const data = await response.json();
        
        if (data.alerts.length > 0) {
            showAlertNotification(data.alerts);
        }
    } catch (error) {
        console.error('Error checking alerts:', error);
    }
}

function showAlertNotification(alerts) {
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) return;
    
    alertContainer.innerHTML = '';
    
    alerts.forEach(alert => {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${alert.level.toLowerCase()} p-3 mb-2 rounded`;
        alertDiv.innerHTML = `
            <i class="fas fa-exclamation-triangle mr-2"></i>
            ${alert.message}
        `;
        alertContainer.appendChild(alertDiv);
    });
}

// Initialize everything when page loads
document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    updateRealTimeMetrics();  // Your existing function
    updateCharts();
    
    // Update charts every 10 seconds
    setInterval(updateCharts, 10000);
    
    // Check alerts every 30 seconds
    setInterval(checkAlerts, 30000);
    
    // Connect to SSE stream for live updates
    connectToEventStream();
});

// Connect to Server-Sent Events
function connectToEventStream() {
    const eventSource = new EventSource('/api/metrics/live');
    
    eventSource.onmessage = function(event) {
        const data = JSON.parse(event.data);
        updateDashboardWithData(data);
    };
    
    eventSource.onerror = function(error) {
        console.error('EventSource failed:', error);
        eventSource.close();
        // Reconnect after 5 seconds
        setTimeout(connectToEventStream, 5000);
    };
}

function updateDashboardWithData(data) {
    // Update your dashboard UI with real-time data
    // This complements the updateRealTimeMetrics function
}