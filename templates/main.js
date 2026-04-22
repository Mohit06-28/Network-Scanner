// Main JavaScript for Network Scanner

// Global variables
let currentUser = null;
let wsConnection = null;
let scanInterval = null;

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatDuration(seconds) {
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes} min ${remainingSeconds.toFixed(0)} sec`;
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '300px';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

function showLoading(show = true) {
    const loader = document.getElementById('globalLoader');
    if (loader) {
        loader.style.display = show ? 'flex' : 'none';
    }
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// API functions
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(endpoint, options);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'API call failed');
        }
        
        return result;
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        showNotification(error.message, 'danger');
        throw error;
    }
}

// Scan management
async function startScan(config) {
    showLoading(true);
    
    try {
        const result = await apiCall('/api/scan', 'POST', config);
        
        if (result.success) {
            showNotification('Scan started successfully', 'success');
            return result.scan_id;
        }
    } catch (error) {
        showNotification('Failed to start scan', 'danger');
        return null;
    } finally {
        showLoading(false);
    }
}

async function getScanStatus(scanId) {
    try {
        return await apiCall(`/api/scan-status/${scanId}`);
    } catch (error) {
        console.error('Failed to get scan status:', error);
        return null;
    }
}

async function getScanResults(scanId) {
    try {
        return await apiCall(`/api/scan-results/${scanId}`);
    } catch (error) {
        console.error('Failed to get scan results:', error);
        return null;
    }
}

// Network functions
async function discoverNetwork(networkCidr, scanPorts = false) {
    showLoading(true);
    
    try {
        const result = await apiCall('/api/network-map', 'POST', {
            network: networkCidr,
            scan_ports: scanPorts
        });
        
        if (result.success) {
            showNotification(`Found ${result.hosts_found} hosts`, 'success');
            return result;
        }
    } catch (error) {
        showNotification('Network discovery failed', 'danger');
        return null;
    } finally {
        showLoading(false);
    }
}

// Report functions
async function exportReport(scanId, format = 'json') {
    try {
        const response = await fetch(`/api/export-report/${scanId}?format=${format}`);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scan_report_${scanId}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            showNotification('Report exported successfully', 'success');
        } else {
            throw new Error('Export failed');
        }
    } catch (error) {
        showNotification('Failed to export report', 'danger');
    }
}

// Authentication
async function login(identifier, password) {
    showLoading(true);
    
    try {
        const result = await apiCall('/login', 'POST', { identifier, password });
        
        if (result.success) {
            localStorage.setItem('token', result.token);
            localStorage.setItem('user', JSON.stringify(result.user));
            showNotification('Login successful', 'success');
            window.location.href = '/dashboard';
        }
    } catch (error) {
        showNotification('Login failed', 'danger');
    } finally {
        showLoading(false);
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

function isAuthenticated() {
    return !!localStorage.getItem('token');
}

// WebSocket connection for real-time updates
function connectWebSocket() {
    const token = localStorage.getItem('token');
    if (!token) return;
    
    const wsUrl = `ws://${window.location.host}/ws?token=${token}`;
    wsConnection = new WebSocket(wsUrl);
    
    wsConnection.onopen = () => {
        console.log('WebSocket connected');
    };
    
    wsConnection.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    wsConnection.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    wsConnection.onclose = () => {
        console.log('WebSocket disconnected');
        setTimeout(connectWebSocket, 5000);
    };
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'scan_progress':
            updateScanProgress(data);
            break;
        case 'scan_complete':
            onScanComplete(data);
            break;
        case 'vulnerability_found':
            onVulnerabilityFound(data);
            break;
        case 'notification':
            showNotification(data.message, data.level);
            break;
        default:
            console.log('Unknown message type:', data.type);
    }
}

// UI Updates
function updateScanProgress(data) {
    const progressBar = document.getElementById('scanProgress');
    const statusText = document.getElementById('scanStatus');
    
    if (progressBar) {
        const percent = (data.scanned / data.total) * 100;
        progressBar.style.width = `${percent}%`;
        progressBar.textContent = `${Math.round(percent)}%`;
    }
    
    if (statusText) {
        statusText.textContent = `Scanning ${data.current_target} - ${data.scanned}/${data.total} ports (${data.open_ports} open)`;
    }
}

function onScanComplete(data) {
    showNotification(`Scan completed! Found ${data.open_ports} open ports`, 'success');
    
    const resultsDiv = document.getElementById('scanResults');
    if (resultsDiv) {
        displayScanResults(data.results);
    }
}

function onVulnerabilityFound(data) {
    showNotification(`Vulnerability found on ${data.host}:${data.port} - ${data.severity}`, 'warning');
}

// Display functions
function displayScanResults(results) {
    const container = document.getElementById('scanResults');
    if (!container) return;
    
    let html = '<table class="data-table">';
    html += '<thead><tr><th>Port</th><th>Protocol</th><th>Status</th><th>Service</th><th>Banner</th></tr></thead><tbody>';
    
    for (const [port, info] of Object.entries(results)) {
        const statusClass = info.open ? 'status-open' : 'status-closed';
        const statusText = info.open ? 'OPEN' : 'CLOSED';
        
        html += `
            <tr>
                <td>${port}</td>
                <td>${info.protocol || 'tcp'}</td>
                <td><span class="${statusClass}">${statusText}</span></td>
                <td>${info.service || '-'}</td>
                <td><small>${(info.banner || '-').substring(0, 50)}</small></td>
            </tr>
        `;
    }
    
    html += '</tbody></table>';
    container.innerHTML = html;
}

function displayNetworkTopology(devices) {
    const container = document.getElementById('networkTopology');
    if (!container) return;
    
    let html = '<div class="network-topology">';
    
    devices.forEach(device => {
        html += `
            <div class="network-node" data-ip="${device.ip}">
                <div class="node-icon">
                    <i class="fas ${device.type === 'router' ? 'fa-router' : 'fa-server'}"></i>
                </div>
                <div class="node-info">
                    <strong>${device.ip}</strong><br>
                    <small>${device.hostname || device.vendor || 'Unknown'}</small>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// Chart functions
function createPerformanceChart(ctx, data) {
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'CPU Time (ms)',
                data: data.cpu_times,
                borderColor: '#f56565',
                backgroundColor: 'rgba(245, 101, 101, 0.1)',
                tension: 0.4
            }, {
                label: 'GPU Time (ms)',
                data: data.gpu_times,
                borderColor: '#48bb78',
                backgroundColor: 'rgba(72, 187, 120, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Performance Comparison'
                }
            }
        }
    });
}

function createPortChart(ctx, ports) {
    const portCounts = {};
    ports.forEach(port => {
        portCounts[port] = (portCounts[port] || 0) + 1;
    });
    
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(portCounts),
            datasets: [{
                data: Object.values(portCounts),
                backgroundColor: [
                    '#667eea', '#764ba2', '#f093fb', '#f5576c',
                    '#4facfe', '#00f2fe', '#43e97b', '#38f9d7'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => {
        new bootstrap.Tooltip(tooltip);
    });
    
    // Initialize popovers
    const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    popovers.forEach(popover => {
        new bootstrap.Popover(popover);
    });
    
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    // Mobile menu toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebar = document.querySelector('.sidebar');
    
    if (mobileMenuBtn && sidebar) {
        mobileMenuBtn.addEventListener('click', () => {
            sidebar.classList.toggle('active');
        });
    }
    
    // Connect WebSocket if authenticated
    if (isAuthenticated()) {
        connectWebSocket();
    }
});

// Export functions for use in other files
window.utils = {
    formatBytes,
    formatDate,
    formatDuration,
    showNotification,
    showLoading,
    debounce
};

window.api = {
    apiCall,
    startScan,
    getScanStatus,
    getScanResults,
    discoverNetwork,
    exportReport
};

window.auth = {
    login,
    logout,
    isAuthenticated
};