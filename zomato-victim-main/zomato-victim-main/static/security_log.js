/**
 * Security Monitoring and Vulnerability Logging
 * Provides real-time monitoring of security scans and vulnerability detection
 */

// Initialize global variables
let logQueue = [];
let vulnerabilityQueue = [];
let scanInProgress = false;
let scanTarget = null;
let scanEndpoints = [];
let scanProgress = 0;
let vulnerabilityCount = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0
};
let longPollingActive = false;
let logPollingInterval = null;
let statusPollingInterval = null;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the dashboard
    initDashboard();
    
    // Set up event listeners
    document.getElementById('start-scan-btn').addEventListener('click', startScan);
    document.getElementById('stop-scan-btn').addEventListener('click', stopScan);
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
    document.getElementById('download-logs-btn').addEventListener('click', downloadLogs);
    
    // Add event listeners to target list items if they exist
    const targetItems = document.querySelectorAll('.target-list li');
    targetItems.forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from all targets
            targetItems.forEach(target => target.classList.remove('active'));
            // Add active class to clicked target
            this.classList.add('active');
            // Set the scan target
            scanTarget = this.getAttribute('data-target');
            // Update UI
            updateTargetInfo();
        });
    });
    
    // Start auto-polling for logs
    startLogPolling();
});

/**
 * Initialize the dashboard
 */
function initDashboard() {
    // Set initial state
    updateScanStatus({
        running: false,
        progress: 0,
        message: 'Ready to scan',
        error: null
    });
    
    // Add an initial log message
    addLogEntry('info', 'Security monitoring dashboard initialized');
    addLogEntry('info', 'Ready to scan for vulnerabilities and exploits');
    
    // Check for active scans
    checkActiveScans();
}

/**
 * Check if there are any active scans
 */
function checkActiveScans() {
    fetch('/admin/scan_status')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                scanInProgress = true;
                updateUIForActiveScan();
                
                // Start polling for scan updates
                startStatusPolling();
            }
        })
        .catch(error => {
            console.error('Error checking for active scans:', error);
            addLogEntry('error', 'Failed to check for active scans: ' + error.message);
        });
}

/**
 * Start a new security scan
 */
function startScan() {
    if (scanInProgress) {
        addLogEntry('warning', 'A scan is already in progress');
        return;
    }
    
    // Validate scan target
    if (!scanTarget) {
        scanTarget = document.querySelector('.target-list li.active')?.getAttribute('data-target') || window.location.origin;
    }
    
    addLogEntry('info', `Initiating security scan against target: ${scanTarget}`);
    
    // Disable start button and enable stop button
    document.getElementById('start-scan-btn').disabled = true;
    document.getElementById('stop-scan-btn').disabled = false;
    
    // Reset vulnerability counters
    vulnerabilityCount = {
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0
    };
    updateVulnerabilityCounters();
    
    // Mark scan as in progress
    scanInProgress = true;
    
    // Make API call to start scan
    fetch('/admin/live_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: scanTarget })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            addLogEntry('success', 'Scan initiated successfully');
            // Start polling for scan status and logs
            startStatusPolling();
        } else {
            scanInProgress = false;
            addLogEntry('error', `Failed to start scan: ${data.error}`);
            document.getElementById('start-scan-btn').disabled = false;
            document.getElementById('stop-scan-btn').disabled = true;
        }
    })
    .catch(error => {
        scanInProgress = false;
        addLogEntry('error', `Error starting scan: ${error.message}`);
        document.getElementById('start-scan-btn').disabled = false;
        document.getElementById('stop-scan-btn').disabled = true;
    });
}

/**
 * Stop the current security scan
 */
function stopScan() {
    if (!scanInProgress) {
        addLogEntry('warning', 'No scan is currently running');
        return;
    }
    
    addLogEntry('info', 'Attempting to stop the current scan...');
    
    fetch('/admin/stop_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            scanInProgress = false;
            addLogEntry('info', 'Scan stopped successfully');
            
            // Update UI
            document.getElementById('start-scan-btn').disabled = false;
            document.getElementById('stop-scan-btn').disabled = true;
            updateScanStatus({
                running: false,
                progress: 0,
                message: 'Scan stopped by user',
                error: null
            });
            
            // Stop polling
            stopStatusPolling();
        } else {
            addLogEntry('error', `Failed to stop scan: ${data.error}`);
        }
    })
    .catch(error => {
        addLogEntry('error', `Error stopping scan: ${error.message}`);
    });
}

/**
 * Start polling for scan status updates
 */
function startStatusPolling() {
    if (statusPollingInterval) {
        clearInterval(statusPollingInterval);
    }
    
    statusPollingInterval = setInterval(() => {
        fetch('/admin/scan_status')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'running') {
                    updateScanStatus({
                        running: true,
                        progress: data.progress || 0,
                        message: data.message || 'Scanning...',
                        error: null
                    });
                } else if (data.status === 'complete') {
                    scanInProgress = false;
                    addLogEntry('success', 'Scan completed successfully');
                    
                    // Update UI
                    document.getElementById('start-scan-btn').disabled = false;
                    document.getElementById('stop-scan-btn').disabled = true;
                    updateScanStatus({
                        running: false,
                        progress: 100,
                        message: 'Scan completed',
                        error: null
                    });
                    
                    // Get final results
                    fetchFinalResults();
                    
                    // Stop polling
                    stopStatusPolling();
                } else if (data.status === 'failed') {
                    scanInProgress = false;
                    addLogEntry('error', `Scan failed: ${data.error}`);
                    
                    // Update UI
                    document.getElementById('start-scan-btn').disabled = false;
                    document.getElementById('stop-scan-btn').disabled = true;
                    updateScanStatus({
                        running: false,
                        progress: 0,
                        message: 'Scan failed',
                        error: data.error
                    });
                    
                    // Stop polling
                    stopStatusPolling();
                }
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
            });
    }, 2000); // Check every 2 seconds
}

/**
 * Stop polling for scan status updates
 */
function stopStatusPolling() {
    if (statusPollingInterval) {
        clearInterval(statusPollingInterval);
        statusPollingInterval = null;
    }
}

/**
 * Start polling for log updates
 */
function startLogPolling() {
    if (logPollingInterval) {
        clearInterval(logPollingInterval);
    }
    
    // Set last log ID to 0 (start)
    let lastLogId = 0;
    
    logPollingInterval = setInterval(() => {
        fetch(`/admin/logs?since=${lastLogId}`)
            .then(response => response.json())
            .then(data => {
                if (data.logs && data.logs.length > 0) {
                    // Process new logs
                    data.logs.forEach(log => {
                        // Add log entry to the UI
                        addLogEntry(log.level, log.message, false);
                        
                        // Update last log ID
                        if (log.id > lastLogId) {
                            lastLogId = log.id;
                        }
                        
                        // If this is a vulnerability detection log, process it
                        if (log.vulnerability) {
                            processVulnerability(log.vulnerability);
                        }
                    });
                }
                
                // Process vulnerability count updates
                if (data.vulnerabilities) {
                    vulnerabilityCount = data.vulnerabilities;
                    updateVulnerabilityCounters();
                }
                
                // Process scan endpoints if available
                if (data.endpoints) {
                    scanEndpoints = data.endpoints;
                    updateEndpointList();
                }
            })
            .catch(error => {
                console.error('Error polling for logs:', error);
            });
    }, 1000); // Check every second
}

/**
 * Stop polling for log updates
 */
function stopLogPolling() {
    if (logPollingInterval) {
        clearInterval(logPollingInterval);
        logPollingInterval = null;
    }
}

/**
 * Fetch final scan results
 */
function fetchFinalResults() {
    fetch('/static/scan_results/latest.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch final results');
            }
            return response.json();
        })
        .then(data => {
            // Update vulnerability counters with final results
            vulnerabilityCount = {
                high: data.summary.high_risk || 0,
                medium: data.summary.medium_risk || 0,
                low: data.summary.low_risk || 0,
                info: data.summary.informational || 0,
                total: data.alerts.length
            };
            updateVulnerabilityCounters();
            
            // Add summary log
            addLogEntry('success', `Scan completed. Found ${vulnerabilityCount.total} vulnerabilities: ${vulnerabilityCount.high} high, ${vulnerabilityCount.medium} medium, ${vulnerabilityCount.low} low risk.`);
            
            // Process each vulnerability
            data.alerts.forEach(alert => {
                processVulnerability({
                    id: alert.alertId,
                    name: alert.alert,
                    risk: alert.risk,
                    url: alert.url,
                    description: alert.description,
                    solution: alert.solution,
                    reference: alert.reference,
                    cweid: alert.cweid,
                    evidence: alert.evidence || ''
                });
            });
        })
        .catch(error => {
            console.error('Error fetching final results:', error);
            addLogEntry('error', `Failed to fetch final results: ${error.message}`);
        });
}

/**
 * Process a detected vulnerability
 */
function processVulnerability(vulnerability) {
    // Add to vulnerability queue
    vulnerabilityQueue.push(vulnerability);
    
    // Add a log entry for the vulnerability
    const riskLevel = vulnerability.risk.toLowerCase();
    addLogEntry(
        riskLevel === 'high' ? 'error' : 
        riskLevel === 'medium' ? 'warning' : 
        riskLevel === 'low' ? 'info' : 'info',
        `Detected: ${vulnerability.name} (${vulnerability.risk} Risk) at ${vulnerability.url}`
    );
    
    // Update UI if needed
    updateVulnerabilityDisplay();
}

/**
 * Update the display for vulnerabilities
 */
function updateVulnerabilityDisplay() {
    const vulnerabilityContainer = document.getElementById('vulnerability-container');
    if (!vulnerabilityContainer) return;
    
    // If the container is hidden, show it
    vulnerabilityContainer.style.display = 'block';
    
    // Get the latest vulnerability
    const vulnerability = vulnerabilityQueue[vulnerabilityQueue.length - 1];
    if (!vulnerability) return;
    
    // Update the vulnerability details
    const vulnTitle = document.getElementById('vulnerability-title');
    if (vulnTitle) {
        vulnTitle.innerHTML = `<i class="fas fa-bug"></i> <h3>${vulnerability.name}</h3>`;
        
        // Add risk badge
        const riskClass = vulnerability.risk === 'High' ? 'high' : 
                         vulnerability.risk === 'Medium' ? 'medium' : 'low';
        vulnTitle.innerHTML += `<span class="vulnerability-badge ${riskClass}">${vulnerability.risk}</span>`;
    }
    
    // Update sections
    updateVulnerabilitySection('url-section', 'Target URL', vulnerability.url);
    updateVulnerabilitySection('description-section', 'Description', vulnerability.description);
    updateVulnerabilitySection('solution-section', 'Solution', vulnerability.solution);
    
    if (vulnerability.evidence) {
        updateVulnerabilitySection('evidence-section', 'Evidence', vulnerability.evidence);
    }
    
    if (vulnerability.cweid) {
        updateVulnerabilitySection('cwe-section', 'CWE ID', `CWE-${vulnerability.cweid}`);
    }
}

/**
 * Update a section in the vulnerability details
 */
function updateVulnerabilitySection(id, title, content) {
    const section = document.getElementById(id);
    if (!section) return;
    
    section.innerHTML = `<h4>${title}</h4><pre>${content}</pre>`;
}

/**
 * Add a log entry to the log window
 */
function addLogEntry(level, message, scrollToBottom = true) {
    // Create log entry
    const logEntry = {
        timestamp: new Date(),
        level: level,
        message: message
    };
    
    // Add to queue
    logQueue.push(logEntry);
    
    // Format timestamp
    const formattedTime = logEntry.timestamp.toTimeString().split(' ')[0];
    
    // Create HTML for log entry
    const logHtml = `
        <div class="log-entry">
            <span class="timestamp">[${formattedTime}]</span>
            <span class="level ${level}">${level.toUpperCase()}</span>
            <span class="message">${formatLogMessage(message)}</span>
        </div>
    `;
    
    // Append to log window
    const logWindow = document.getElementById('log-window');
    if (logWindow) {
        logWindow.innerHTML += logHtml;
        
        // Scroll to bottom if requested
        if (scrollToBottom) {
            logWindow.scrollTop = logWindow.scrollHeight;
        }
    }
}

/**
 * Format a log message to highlight important parts
 */
function formatLogMessage(message) {
    // Highlight URLs
    message = message.replace(/(https?:\/\/[^\s]+)/g, '<span class="highlight">$1</span>');
    
    // Highlight commands or technical terms
    message = message.replace(/(ZAP|SQL Injection|XSS|CSRF|Authentication Bypass|Directory Traversal)/g, '<span class="command">$1</span>');
    
    return message;
}

/**
 * Clear all logs from the log window
 */
function clearLogs() {
    const logWindow = document.getElementById('log-window');
    if (logWindow) {
        logWindow.innerHTML = '';
        logQueue = [];
        addLogEntry('info', 'Logs cleared');
    }
}

/**
 * Download logs as a text file
 */
function downloadLogs() {
    // Format logs for download
    let logText = '';
    logQueue.forEach(log => {
        const timestamp = log.timestamp.toISOString();
        logText += `[${timestamp}] [${log.level.toUpperCase()}] ${log.message}\n`;
    });
    
    // Create download link
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_scan_log_${new Date().toISOString().replace(/:/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    
    // Clean up
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

/**
 * Update the scan status display
 */
function updateScanStatus(status) {
    const progressBar = document.getElementById('progress-bar-inner');
    const statusText = document.getElementById('scan-status-text');
    
    if (progressBar) {
        progressBar.style.width = `${status.progress}%`;
    }
    
    if (statusText) {
        if (status.running) {
            statusText.textContent = status.message || 'Scanning...';
        } else if (status.error) {
            statusText.textContent = `Error: ${status.error}`;
        } else {
            statusText.textContent = status.message || 'Ready';
        }
    }
    
    // Update scan control buttons
    const startButton = document.getElementById('start-scan-btn');
    const stopButton = document.getElementById('stop-scan-btn');
    
    if (startButton) {
        startButton.disabled = status.running;
    }
    
    if (stopButton) {
        stopButton.disabled = !status.running;
    }
}

/**
 * Update vulnerability counters in the UI
 */
function updateVulnerabilityCounters() {
    // Update each counter
    updateCounter('high-risk-count', vulnerabilityCount.high);
    updateCounter('medium-risk-count', vulnerabilityCount.medium);
    updateCounter('low-risk-count', vulnerabilityCount.low);
    updateCounter('info-count', vulnerabilityCount.info);
    updateCounter('total-count', vulnerabilityCount.total);
}

/**
 * Update a specific counter element
 */
function updateCounter(id, value) {
    const counter = document.getElementById(id);
    if (counter) {
        counter.textContent = value;
    }
}

/**
 * Update the endpoint list
 */
function updateEndpointList() {
    const endpointList = document.getElementById('endpoint-list');
    if (!endpointList || scanEndpoints.length === 0) return;
    
    // Clear current list
    endpointList.innerHTML = '';
    
    // Add each endpoint
    scanEndpoints.forEach(endpoint => {
        const li = document.createElement('li');
        li.innerHTML = `<i class="fas fa-link"></i> ${endpoint.url} <span class="endpoint-method">${endpoint.method}</span>`;
        
        // If the endpoint has a vulnerability, highlight it
        if (endpoint.vulnerable) {
            li.classList.add('vulnerable');
            li.innerHTML += ` <span class="endpoint-vulnerable">Vulnerable</span>`;
        }
        
        endpointList.appendChild(li);
    });
}

/**
 * Update target information display
 */
function updateTargetInfo() {
    const targetInfo = document.getElementById('target-info');
    if (targetInfo && scanTarget) {
        targetInfo.textContent = scanTarget;
    }
}

/**
 * Update UI for active scan
 */
function updateUIForActiveScan() {
    document.getElementById('start-scan-btn').disabled = true;
    document.getElementById('stop-scan-btn').disabled = false;
    
    // Start status polling
    startStatusPolling();
} 