/**
 * OWASP ZAP Scan Results Display Script
 * Handles loading and displaying vulnerability scan results
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load the latest scan results when the page loads
    loadLatestResults();

    // Set up event listeners
    const startScanButton = document.getElementById('start-scan');
    if (startScanButton) {
        startScanButton.addEventListener('click', startScan);
    }

    const historyToggle = document.getElementById('toggle-history');
    if (historyToggle) {
        historyToggle.addEventListener('click', toggleHistory);
    }
});

/**
 * Load the latest scan results from the JSON file
 */
function loadLatestResults() {
    fetch('/static/scan_results/latest.json')
        .then(response => {
            if (response.ok) {
                return response.json();
            } else if (response.status === 404) {
                // No scan results yet
                displayNoResults();
                return null;
            } else {
                throw new Error('Failed to load results');
            }
        })
        .then(data => {
            if (data) {
                displayResults(data);
                loadScanHistory();
            }
        })
        .catch(error => {
            console.error('Error loading scan results:', error);
            displayNoResults();
        });
}

/**
 * Display a message when no scan results are available
 */
function displayNoResults() {
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) {
        resultsContainer.innerHTML = `
            <div class="no-results">
                <i class="fas fa-search"></i>
                <h2>No Scan Results Available</h2>
                <p>Run your first scan to see vulnerability results.</p>
                <button id="first-scan" class="action-button">Start First Scan</button>
            </div>
        `;
        
        const firstScanButton = document.getElementById('first-scan');
        if (firstScanButton) {
            firstScanButton.addEventListener('click', startScan);
        }
    }
}

/**
 * Display the scan results on the page
 */
function displayResults(data) {
    const resultsContainer = document.getElementById('results-container');
    if (!resultsContainer) return;

    // Format scan date
    const scanDate = new Date(data.scan_date);
    const formattedDate = scanDate.toLocaleString();
    
    // Summary stats cards
    let statsHtml = `
        <div class="scan-info">
            <p><strong>Target:</strong> ${data.target}</p>
            <p><strong>Scan completed:</strong> <span class="scan-date">${formattedDate}</span></p>
        </div>
        <div class="summary-stats">
            <div class="stat-card high-risk">
                <h3>High Risk</h3>
                <div class="stat-number">${data.summary.high_risk}</div>
                <p>Critical vulnerabilities</p>
            </div>
            <div class="stat-card medium-risk">
                <h3>Medium Risk</h3>
                <div class="stat-number">${data.summary.medium_risk}</div>
                <p>Significant vulnerabilities</p>
            </div>
            <div class="stat-card low-risk">
                <h3>Low Risk</h3>
                <div class="stat-number">${data.summary.low_risk}</div>
                <p>Minor vulnerabilities</p>
            </div>
            <div class="stat-card info-risk">
                <h3>Informational</h3>
                <div class="stat-number">${data.summary.informational || 0}</div>
                <p>Information items</p>
            </div>
        </div>
    `;
    
    // Table of alerts
    let alertsTableHtml = `
        <table id="alerts-table">
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Alert</th>
                    <th>URL</th>
                    <th>CWE ID</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    // Sort alerts by risk level (High to Low)
    const riskOrder = { 'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3 };
    data.alerts.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
    
    data.alerts.forEach((alert, index) => {
        const riskClass = alert.risk === 'High' ? 'high' : 
                         alert.risk === 'Medium' ? 'medium' : 
                         alert.risk === 'Low' ? 'low' : 'info';
        
        alertsTableHtml += `
            <tr class="alert-row" data-alert-id="${index}">
                <td><span class="badge badge-${riskClass}">${alert.risk}</span></td>
                <td>${alert.alert}</td>
                <td>${shortenUrl(alert.url)}</td>
                <td>${alert.cweid || 'N/A'}</td>
                <td><span class="show-details" data-alert-id="${index}">View Details</span></td>
            </tr>
            <tr class="details-row" id="details-${index}" style="display: none;">
                <td colspan="5">
                    <div class="details-section">
                        <h4>Description</h4>
                        <div class="alert-details">${alert.description}</div>
                        
                        <h4>Solution</h4>
                        <div class="alert-details">${alert.solution}</div>
                        
                        ${alert.otherinfo ? `
                            <h4>Additional Information</h4>
                            <div class="alert-details">${alert.otherinfo}</div>
                        ` : ''}
                        
                        <h4>Reference</h4>
                        <div class="alert-details">${formatReferences(alert.reference)}</div>
                    </div>
                </td>
            </tr>
        `;
    });
    
    alertsTableHtml += `
            </tbody>
        </table>
    `;
    
    resultsContainer.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Scan Results Summary</h2>
                <button id="start-scan" class="action-button">Run New Scan</button>
            </div>
            <div class="card-body">
                ${statsHtml}
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Vulnerability Details</h2>
                <div>
                    <button id="toggle-history" class="action-button">View Scan History</button>
                </div>
            </div>
            <div class="card-body">
                ${alertsTableHtml}
            </div>
        </div>
        
        <div id="history-container" class="card" style="display: none;">
            <div class="card-header">
                <h2 class="card-title">Scan History</h2>
            </div>
            <div class="card-body">
                <ul id="history-list" class="history-list">
                    <li>Loading history...</li>
                </ul>
            </div>
        </div>
    `;
    
    // Add event listeners to the 'View Details' buttons
    document.querySelectorAll('.show-details').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-alert-id');
            const detailsRow = document.getElementById(`details-${alertId}`);
            
            if (detailsRow.style.display === 'none') {
                detailsRow.style.display = 'table-row';
                this.textContent = 'Hide Details';
            } else {
                detailsRow.style.display = 'none';
                this.textContent = 'View Details';
            }
        });
    });
    
    // Add event listener to the new start scan button
    const startScanButton = document.getElementById('start-scan');
    if (startScanButton) {
        startScanButton.addEventListener('click', startScan);
    }
    
    const historyToggle = document.getElementById('toggle-history');
    if (historyToggle) {
        historyToggle.addEventListener('click', toggleHistory);
    }
}

/**
 * Start a new ZAP scan
 */
function startScan() {
    // Show loading state
    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Starting Scan...';
    button.disabled = true;
    
    // Call the scan endpoint
    fetch('/admin/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            button.textContent = 'Scan Running...';
            // Poll for scan completion
            pollScanStatus();
        } else {
            alert('Failed to start scan: ' + data.error);
            button.textContent = originalText;
            button.disabled = false;
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        alert('An error occurred while starting the scan.');
        button.textContent = originalText;
        button.disabled = false;
    });
}

/**
 * Poll the scan status until complete
 */
function pollScanStatus() {
    const interval = setInterval(() => {
        fetch('/admin/scan_status')
            .then(response => response.json())
            .then(data => {
                const startScanButton = document.getElementById('start-scan');
                
                if (data.status === 'complete') {
                    clearInterval(interval);
                    if (startScanButton) {
                        startScanButton.textContent = 'Run New Scan';
                        startScanButton.disabled = false;
                    }
                    // Reload the results
                    loadLatestResults();
                } else if (data.status === 'failed') {
                    clearInterval(interval);
                    alert('Scan failed: ' + data.error);
                    if (startScanButton) {
                        startScanButton.textContent = 'Run New Scan';
                        startScanButton.disabled = false;
                    }
                } else {
                    // Still running
                    if (startScanButton) {
                        startScanButton.textContent = `Scanning... ${data.progress || ''}`;
                    }
                }
            })
            .catch(error => {
                console.error('Error checking scan status:', error);
                clearInterval(interval);
                const startScanButton = document.getElementById('start-scan');
                if (startScanButton) {
                    startScanButton.textContent = 'Run New Scan';
                    startScanButton.disabled = false;
                }
            });
    }, 5000); // Check every 5 seconds
}

/**
 * Load the scan history
 */
function loadScanHistory() {
    fetch('/admin/scan_history')
        .then(response => response.json())
        .then(data => {
            const historyList = document.getElementById('history-list');
            if (!historyList) return;
            
            if (data.history && data.history.length > 0) {
                let historyHtml = '';
                data.history.forEach(item => {
                    const scanDate = new Date(item.date);
                    historyHtml += `
                        <li class="history-item">
                            <span class="history-date">${scanDate.toLocaleString()}</span>
                            <p>Target: ${item.target}</p>
                            <p>
                                <strong>Results:</strong> 
                                <span class="badge badge-high">${item.high} High</span>
                                <span class="badge badge-medium">${item.medium} Medium</span>
                                <span class="badge badge-low">${item.low} Low</span>
                            </p>
                            <button class="action-button" onclick="loadScanResult('${item.file}')">View Scan</button>
                        </li>
                    `;
                });
                historyList.innerHTML = historyHtml;
            } else {
                historyList.innerHTML = '<li>No scan history available</li>';
            }
        })
        .catch(error => {
            console.error('Error loading scan history:', error);
            const historyList = document.getElementById('history-list');
            if (historyList) {
                historyList.innerHTML = '<li>Failed to load scan history</li>';
            }
        });
}

/**
 * Load a specific scan result from history
 */
function loadScanResult(filename) {
    fetch(`/static/scan_results/${filename}`)
        .then(response => response.json())
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            console.error('Error loading specific scan result:', error);
            alert('Failed to load the selected scan result.');
        });
}

/**
 * Toggle the history display
 */
function toggleHistory() {
    const historyContainer = document.getElementById('history-container');
    if (historyContainer) {
        if (historyContainer.style.display === 'none') {
            historyContainer.style.display = 'block';
            document.getElementById('toggle-history').textContent = 'Hide Scan History';
        } else {
            historyContainer.style.display = 'none';
            document.getElementById('toggle-history').textContent = 'View Scan History';
        }
    }
}

/**
 * Format references to be clickable links
 */
function formatReferences(references) {
    if (!references) return 'No references available';
    
    // Split by newlines and create links
    return references.split('\n')
        .map(ref => {
            // Check if the reference is a URL
            if (ref.startsWith('http') || ref.startsWith('www')) {
                return `<a href="${ref}" target="_blank" rel="noopener">${ref}</a>`;
            }
            return ref;
        })
        .join('<br>');
}

/**
 * Shorten a URL for display
 */
function shortenUrl(url) {
    if (!url) return 'N/A';
    
    try {
        const urlObj = new URL(url);
        const path = urlObj.pathname;
        if (path.length > 30) {
            return urlObj.origin + '/' + path.substring(0, 15) + '...' + path.substring(path.length - 10);
        }
        return urlObj.origin + path;
    } catch (e) {
        return url.length > 50 ? url.substring(0, 47) + '...' : url;
    }
} 