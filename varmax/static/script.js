let chart;
let threatsData = [];
let filteredThreats = [];
let selectedThreat = null;
let chartType = 'doughnut'; // Default chart type
let sortDirection = 'desc'; // Default sort direction

// Initialize the dashboard when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    updateCurrentTime();
    setInterval(updateCurrentTime, 60000);
    initChart();
    loadDatasets();
    loadPyodModels();
    
    // Set up event listeners
    document.getElementById('test-form').addEventListener('submit', function(e) {
        e.preventDefault();
        startLiveDetection(); // Default to live detection
    });
    
    // Update form UI to focus on live detection
    const testForm = document.getElementById('test-form');
    const submitButton = testForm.querySelector('button[type="submit"]');
    submitButton.textContent = 'Start Live Detection';
    submitButton.classList.add('btn-primary');
    
    // Update form instructions
    const formInstructions = document.querySelector('.card-header h5');
    if (formInstructions) {
        formInstructions.textContent = 'Live Network Traffic Analysis';
    }
    
    // Add detection parameters section
    const advancedSettingsToggle = document.getElementById('advanced-settings-toggle');
    if (advancedSettingsToggle) {
        // Show advanced settings by default
        const advancedSettings = document.getElementById('advanced-settings');
        if (advancedSettings) {
            advancedSettings.classList.remove('d-none');
            advancedSettingsToggle.innerHTML = '<i class="bi bi-chevron-up"></i> Hide Advanced Settings';
        }
    }
    
    // Event listeners for other UI elements
    document.getElementById('threat-filter').addEventListener('change', function() {
        filterThreats(this.value);
    });
    
    document.getElementById('sort-by').addEventListener('change', function() {
        sortThreats(this.value, sortDirection);
    });
    
    document.getElementById('sort-direction').addEventListener('click', function() {
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
        this.innerHTML = sortDirection === 'asc' ? 
            '<i class="bi bi-sort-up"></i>' : 
            '<i class="bi bi-sort-down"></i>';
        
        sortThreats(document.getElementById('sort-by').value, sortDirection);
    });
    
    document.getElementById('toggle-chart-view').addEventListener('click', function() {
        toggleChartType();
    });
    
    document.getElementById('theme-toggle').addEventListener('click', function() {
        toggleTheme();
    });
});

// Update the current time display
function updateCurrentTime() {
    const now = new Date();
    const options = { 
        weekday: 'long', 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    document.getElementById('current-time').textContent = now.toLocaleDateString('en-US', options);
}

// Toggle between light and dark theme
function toggleTheme() {
    const body = document.body;
    const icon = document.querySelector('#theme-toggle i');
    
    if (body.classList.contains('dark-theme')) {
        body.classList.remove('dark-theme');
        icon.classList.remove('bi-sun');
        icon.classList.add('bi-moon-stars');
    } else {
        body.classList.add('dark-theme');
        icon.classList.remove('bi-moon-stars');
        icon.classList.add('bi-sun');
    }
}

// Load available datasets from API
function loadDatasets() {
    fetch('/api/datasets')
        .then(response => response.json())
        .then(datasets => {
            const select = document.getElementById('test-data-path');
            select.innerHTML = '';
            
            datasets.forEach(dataset => {
                const option = document.createElement('option');
                option.value = dataset.path;
                option.textContent = dataset.name;
                option.dataset.id = dataset.id;
                select.appendChild(option);
            });
            
            loadModelInfo();
        })
        .catch(error => {
            console.error('Error loading datasets:', error);
            showError('Failed to load datasets. Please refresh the page.');
        });
}

// Load model information
function loadModelInfo() {
    fetch('/api/model_info')
        .then(response => response.json())
        .then(info => {
            // Update model info in the UI
            if (info.datasets) {
                info.datasets.forEach(dataset => {
                    const infoElement = document.getElementById(`${dataset.name.toLowerCase().split(' ')[0]}-info`);
                    if (infoElement) {
                        let html = `
                            <div class="mt-3">
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Features:</span>
                                    <strong>${dataset.features}</strong>
                                </div>
                                <div class="d-flex justify-content-between mb-2">
                                    <span>Classes:</span>
                                    <strong>${dataset.classes}</strong>
                                </div>
                            `;
                            
                        if (dataset.distribution) {
                            html += '<div class="mt-3"><h6>Class Distribution</h6>';
                            
                            let totalSamples = 0;
                            Object.values(dataset.distribution).forEach(count => {
                                totalSamples += count;
                            });
                            
                            Object.entries(dataset.distribution).forEach(([className, count]) => {
                                const percentage = (count / totalSamples * 100).toFixed(1);
                                html += `
                                    <div>
                                        <div class="d-flex justify-content-between small mb-1">
                                            <span>${className}</span>
                                            <span>${count} (${percentage}%)</span>
                                        </div>
                                        <div class="progress mb-2" style="height: 6px;">
                                            <div class="progress-bar" style="width: ${percentage}%"></div>
                                        </div>
                                    </div>
                                `;
                            });
                            
                            html += '</div>';
                        }
                        
                        html += '</div>';
                        infoElement.innerHTML = html;
                    }
                });
            }
        })
        .catch(error => {
            console.error('Error loading model info:', error);
        });
}

// Load available PyOD models from API
function loadPyodModels() {
    fetch('/api/pyod_models')
        .then(response => response.json())
        .then(models => {
            const modelsContainer = document.getElementById('pyod-models-list');
            
            let html = '<div class="row">';
            models.forEach(model => {
                html += `
                <div class="col-md-6 mb-3">
                    <div class="card h-100">
                        <div class="card-body p-3">
                            <h6 class="mb-2">${model.name}</h6>
                            <p class="small text-muted mb-0">${model.description}</p>
                        </div>
                    </div>
                </div>`;
            });
            html += '</div>';
            
            modelsContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading PyOD models:', error);
            document.getElementById('pyod-models-list').innerHTML = '<div class="alert alert-warning">Failed to load model information.</div>';
        });
}

// Initialize the statistics chart
function initChart() {
    const ctx = document.getElementById('threat-chart').getContext('2d');
    chart = new Chart(ctx, {
        type: chartType,
        data: {
            labels: ['Zero-Day Threats', 'Anomalies', 'Normal Traffic'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
                borderWidth: 1,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: {
                            size: 12
                        },
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Toggle chart type between doughnut and bar
function toggleChartType() {
    chartType = chartType === 'doughnut' ? 'bar' : 'doughnut';
    
    // Destroy current chart
    chart.destroy();
    
    // Configure chart options based on type
    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: chartType === 'doughnut',
                position: 'right',
                labels: {
                    font: {
                        size: 12
                    },
                    padding: 15
                }
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        const label = context.label || '';
                        const value = context.raw || 0;
                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                        const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                        return `${label}: ${value} (${percentage}%)`;
                    }
                }
            }
        }
    };
    
    // Add scales for bar chart
    if (chartType === 'bar') {
        options.scales = {
            y: {
                beginAtZero: true,
                ticks: {
                    precision: 0
                }
            }
        };
    }
    
    // Re-initialize chart with the same data
    const ctx = document.getElementById('threat-chart').getContext('2d');
    chart = new Chart(ctx, {
        type: chartType,
        data: {
            labels: ['Zero-Day Threats', 'Anomalies', 'Normal Traffic'],
            datasets: [{
                data: [
                    parseInt(document.getElementById('zeroday-count').textContent) || 0,
                    parseInt(document.getElementById('anomaly-count').textContent) || 0,
                    parseInt(document.getElementById('normal-count').textContent) || 0
                ],
                backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
                borderWidth: 1,
                borderColor: '#fff'
            }]
        },
        options: options
    });
}

// Run analysis on the selected dataset
function runAnalysis() {
    const dataPath = document.getElementById('test-data-path').value;
    const maxSamples = document.getElementById('max-samples').value;
    const datasetName = document.getElementById('dataset-name').value;
    const enableAdvanced = document.getElementById('advanced-detection').checked;
    
    showLoading("Analyzing network traffic data...");
    hideMessages();
    
    const requestData = {
        test_data_path: dataPath,
        max_samples: parseInt(maxSamples),
        dataset_name: datasetName,
        advanced_detection: enableAdvanced
    };
    
    fetch('/api/test', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.error) {
            showError('Analysis failed: ' + data.error);
            return;
        }
        
        updateDashboard(data);
        showSuccess('Analysis completed successfully!');
    })
    .catch(error => {
        hideLoading();
        showError('Request failed: ' + error.message);
    });
}

// Update the dashboard with analysis results
function updateDashboard(data) {
    // Update threat counts
    const counts = data.threat_distribution.counts;
    document.getElementById('normal-count').textContent = counts.Normal || 0;
    document.getElementById('anomaly-count').textContent = counts.Anomaly || 0;
    document.getElementById('zeroday-count').textContent = counts['Zero-Day'] || 0;
    
    // Update progress bars
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total > 0) {
        document.getElementById('normal-progress').style.width = `${(counts.Normal || 0) / total * 100}%`;
        document.getElementById('anomaly-progress').style.width = `${(counts.Anomaly || 0) / total * 100}%`;
        document.getElementById('zeroday-progress').style.width = `${(counts['Zero-Day'] || 0) / total * 100}%`;
    }
    
    // Update chart
    chart.data.datasets[0].data = [
        counts['Zero-Day'] || 0,
        counts.Anomaly || 0,
        counts.Normal || 0
    ];
    chart.update();
    
    // Update risk assessment
    const riskBadge = document.getElementById('risk-badge');
    const riskText = document.getElementById('risk-text');
    
    riskBadge.className = 'alert';
    if (data.risk_assessment.includes('CRITICAL')) {
        riskBadge.classList.add('alert-danger');
    } else if (data.risk_assessment.includes('HIGH')) {
        riskBadge.classList.add('alert-warning');
    } else if (data.risk_assessment.includes('MEDIUM')) {
        riskBadge.classList.add('alert-primary');
    } else {
        riskBadge.classList.add('alert-success');
    }
    
    riskText.textContent = data.risk_assessment;
    
    // Update metadata
    document.getElementById('total-records').textContent = data.metadata.total_records;
    document.getElementById('analysis-time').textContent = data.metadata.analysis_time.toFixed(2);
    
    // Store and display threats
    threatsData = data.threats || [];
    filterThreats('all');
}

// Display filtered threats in the UI
function displayThreats() {
    const container = document.getElementById('threats-container');
    
    if (!filteredThreats || filteredThreats.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <i class="bi bi-shield-check fs-1 text-muted"></i>
                <p class="mt-3 text-muted">No network connections to display. Start live detection to see results.</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    filteredThreats.forEach(threat => {
        const isAnomalous = threat.is_anomaly;
        const cardClass = isAnomalous ? 'bg-danger text-white' : 'bg-light';
        const iconClass = isAnomalous ? 'bi-exclamation-triangle-fill' : 'bi-shield-check';
        const confidencePercent = Math.round(threat.confidence * 100);
        
        html += `
            <div class="threat-card ${selectedThreat && selectedThreat.id === threat.id ? 'selected' : ''}" 
                 data-id="${threat.id}" onclick="showThreatDetails(threatsData.find(t => t.id === ${threat.id}))">
                <div class="threat-header ${cardClass}">
                    <div class="d-flex align-items-center">
                        <i class="bi ${iconClass} me-2"></i>
                        <div>
                            ${isAnomalous ? 
                                `<strong>${threat.detected_label}</strong>` : 
                                '<strong>Normal Connection</strong>'}
                            <div class="small">${threat.timestamp_formatted || threat.timestamp}</div>
                        </div>
                    </div>
                    <div class="threat-badge">
                        <span class="badge ${isAnomalous ? 'bg-white text-danger' : 'bg-success'}">
                            ${isAnomalous ? confidencePercent + '%' : 'Normal'}
                        </span>
                    </div>
                </div>
                <div class="threat-body">
                    <div class="d-flex justify-content-between mb-1">
                        <span>Source:</span>
                        <span class="fw-bold">${threat.src_ip}:${threat.src_port}</span>
                    </div>
                    <div class="d-flex justify-content-between mb-1">
                        <span>Destination:</span>
                        <span class="fw-bold">${threat.dst_ip}:${threat.dst_port}</span>
                    </div>
                    <div class="d-flex justify-content-between mb-1">
                        <span>Protocol:</span>
                        <span>${threat.protocol || 'Unknown'}</span>
                    </div>
                    ${threat.service ? 
                        `<div class="d-flex justify-content-between mb-1">
                            <span>Service:</span>
                            <span>${threat.service}</span>
                        </div>` : ''
                    }
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Filter threats based on type
function filterThreats(type) {
    if (type === 'all') {
        filteredThreats = [...threatsData];
    } else if (type === 'true') {
        filteredThreats = threatsData.filter(threat => threat.is_anomaly);
    } else if (type === 'false') {
        filteredThreats = threatsData.filter(threat => !threat.is_anomaly);
    }
    
    displayThreats();
}

// Sort threats by a specific property
function sortThreats(property, direction) {
    filteredThreats.sort((a, b) => {
        let valueA = a[property];
        let valueB = b[property];
        
        // Handle specific properties
        if (property === 'timestamp' && a.timestamp_formatted) {
            valueA = new Date(a.timestamp_formatted || a.timestamp).getTime();
            valueB = new Date(b.timestamp_formatted || b.timestamp).getTime();
        }
        
        if (direction === 'asc') {
            return valueA > valueB ? 1 : -1;
        } else {
            return valueA < valueB ? 1 : -1;
        }
    });
    
    displayThreats();
}

// Update showThreatDetails function to display connection details properly
function showThreatDetails(threat) {
    if (!threat) {
        document.getElementById('anomaly-title').textContent = 'Select a connection to view details';
        document.getElementById('anomaly-type').textContent = '-';
        document.getElementById('anomaly-confidence-value').textContent = '-';
        document.getElementById('anomaly-confidence').style.width = '0%';
        document.getElementById('anomaly-features').innerHTML = '<p class="text-muted">No feature data available</p>';
        document.getElementById('model-predictions').innerHTML = '<p class="text-muted">No prediction data available</p>';
        document.getElementById('source-ip').textContent = '-';
        document.getElementById('dest-ip').textContent = '-';
        document.getElementById('protocol').textContent = '-';
        document.getElementById('service').textContent = '-';
        return;
    }

    selectedThreat = threat;
    
    // Basic information
    const title = threat.is_anomaly ? 
        `Anomaly (#${threat.id}) - ${threat.detected_label}` : 
        `Normal Connection (#${threat.id})`;
    
    document.getElementById('anomaly-title').textContent = title;
    
    // Connection type
    const typeHTML = threat.is_anomaly ?
        `<span class="badge bg-danger">${threat.detected_label}</span>` :
        `<span class="badge bg-success">Normal</span>`;
    document.getElementById('anomaly-type').innerHTML = typeHTML;
    
    // Network details
    document.getElementById('source-ip').textContent = `${threat.src_ip}:${threat.src_port}`;
    document.getElementById('dest-ip').textContent = `${threat.dst_ip}:${threat.dst_port}`;
    document.getElementById('protocol').textContent = threat.protocol || '-';
    document.getElementById('service').textContent = threat.service || '-';
    
    // Confidence
    const confidencePercent = Math.round(threat.confidence * 100);
    document.getElementById('anomaly-confidence-value').textContent = `${confidencePercent}%`;
    
    // Set confidence bar color based on level
    const confidenceBar = document.getElementById('anomaly-confidence');
    confidenceBar.style.width = `${confidencePercent}%`;
    
    if (confidencePercent >= 80) {
        confidenceBar.className = 'confidence-level high';
    } else if (confidencePercent >= 50) {
        confidenceBar.className = 'confidence-level medium';
    } else {
        confidenceBar.className = 'confidence-level low';
    }
    
    // Feature importance (if available)
    let featuresHTML = '';
    if (threat.top_features && Object.keys(threat.top_features).length > 0) {
        featuresHTML = '<div class="features-grid">';
        
        // Convert to array and sort by importance
        const features = Object.entries(threat.top_features)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5); // Show top 5 features
            
        features.forEach(([feature, importance]) => {
            const percent = Math.round(importance * 100);
            featuresHTML += `
                <div class="feature-item">
                    <div class="feature-name">${feature}</div>
                    <div class="feature-bar-container">
                        <div class="feature-bar" style="width: ${percent}%"></div>
                    </div>
                    <div class="feature-value">${percent}%</div>
                </div>
            `;
        });
        
        featuresHTML += '</div>';
    } else {
        featuresHTML = '<p class="text-muted">No feature importance data available</p>';
    }
    
    document.getElementById('anomaly-features').innerHTML = featuresHTML;
    
    // Model predictions
    let predictionsHTML = '';
    if (threat.model_predictions) {
        predictionsHTML = '<ul class="list-group">';
        Object.entries(threat.model_predictions).forEach(([model, prediction]) => {
            const badgeClass = prediction.anomaly ? 'bg-danger' : 'bg-success';
            const predictionText = prediction.anomaly ? 'Anomaly' : 'Normal';
            
            predictionsHTML += `
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    ${model}
                    <span class="badge ${badgeClass}">${predictionText}</span>
                </li>
            `;
        });
        predictionsHTML += '</ul>';
    } else {
        predictionsHTML = `
            <p class="text-muted">
                This detection uses ensemble voting from multiple models
            </p>
        `;
    }
    
    document.getElementById('model-predictions').innerHTML = predictionsHTML;
    
    // Highlight the selected threat in the list
    const threatCards = document.querySelectorAll('.threat-card');
    threatCards.forEach(card => {
        card.classList.remove('selected');
        if (card.dataset.id === threat.id.toString()) {
            card.classList.add('selected');
        }
    });
}

// Show loading overlay
function showLoading(message = "Processing...") {
    const overlay = document.getElementById('loading-overlay');
    const loadingText = document.getElementById('loading-text');
    
    loadingText.textContent = message;
    overlay.classList.remove('d-none');
}

// Hide loading overlay
function hideLoading() {
    document.getElementById('loading-overlay').classList.add('d-none');
}

// Show error message
function showError(message) {
    const errorElement = document.getElementById('error-message');
    document.getElementById('error-text').textContent = message;
    
    errorElement.classList.remove('d-none');
    errorElement.classList.add('show');
    
    setTimeout(() => {
        errorElement.classList.remove('show');
        setTimeout(() => errorElement.classList.add('d-none'), 500);
    }, 5000);
}

// Show success message
function showSuccess(message) {
    const successElement = document.getElementById('success-message');
    document.getElementById('success-text').textContent = message;
    
    successElement.classList.remove('d-none');
    successElement.classList.add('show');
    
    setTimeout(() => {
        successElement.classList.remove('show');
        setTimeout(() => successElement.classList.add('d-none'), 500);
    }, 3000);
}

// Add live detection functionality
function startLiveDetection() {
    // Show loading indicator
    showLoading("Starting live detection...");
    document.getElementById('result-message').innerHTML = '<div class="alert alert-info">Starting live network traffic analysis...</div>';
    
    // Get parameters from form
    const dataset = document.getElementById('test-data-path');
    const datasetName = dataset.options[dataset.selectedIndex].dataset.id === '0' ? 'live_detection' : 
                       dataset.options[dataset.selectedIndex].dataset.id === '1' ? 'kdd' : 'unsw';
    
    // Get detection parameters
    const anomalyProbability = parseFloat(document.getElementById('anomaly-probability').value || 0.2);
    const batchSize = parseInt(document.getElementById('batch-size').value || 50);
    const duration = parseInt(document.getElementById('duration').value || 30);
    const interval = parseFloat(document.getElementById('interval').value || 0.5);
    
    const params = {
        dataset_name: datasetName,
        anomaly_probability: anomalyProbability,
        batch_size: batchSize,
        duration: duration,
        interval: interval
    };
    
    // Call live detection API
    fetch('/api/live_detection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(params)
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.error) {
            showError(`Error: ${data.error}`);
            return;
        }
        
        // Update results
        const results = data.results;
        document.getElementById('result-message').innerHTML = `
            <div class="alert alert-success">
                <h5><i class="bi bi-check-circle-fill"></i> Live Detection Complete</h5>
                <p>${data.message}</p>
                <hr>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Total connections analyzed:</strong> ${results.total}</p>
                        <p><strong>Anomalies detected:</strong> ${results.anomalies}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>True positives:</strong> ${results.true_positives}</p>
                        <p><strong>Detection accuracy:</strong> ${(results.accuracy * 100).toFixed(1)}%</p>
                    </div>
                </div>
            </div>
        `;
        
        // Update chart with anomaly data
        updateChart(results.anomalies, results.total - results.anomalies);
        
        // Display threat details from detection history
        if (data.detection_history && data.detection_history.length > 0) {
            threatsData = data.detection_history;
            
            // Process and display threats
            processThreats(threatsData);
            
            // Show anomalies tab
            const anomaliesTab = document.querySelector('a[href="#anomalies"]');
            if (anomaliesTab) {
                anomaliesTab.click();
            }
        }
        
        // Show detection complete notification
        showNotification('Live Detection Complete', `Analyzed ${results.total} connections with ${results.anomalies} anomalies detected`);
    })
    .catch(error => {
        hideLoading();
        console.error('Error running live detection:', error);
        showError('Failed to run live detection. See console for details.');
    });
}

// Process threats and display them
function processThreats(threats) {
    // Add additional metadata for display
    threatsData = threats.map((threat, index) => {
        const risk = threat.confidence > 0.8 ? 'High' : 
                    threat.confidence > 0.6 ? 'Medium' : 'Low';
        
        return {
            ...threat,
            id: index + 1,
            risk: risk,
            timestamp_formatted: new Date(threat.timestamp).toLocaleString()
        };
    });
    
    // Filter and sort threats
    filteredThreats = [...threatsData];
    sortThreats('confidence', 'desc');
    
    // Update threat stats
    updateThreatStats();
}

// Update threat statistics
function updateThreatStats() {
    const totalThreats = threatsData.length;
    const anomalies = threatsData.filter(t => t.is_anomaly).length;
    const highRisk = threatsData.filter(t => t.risk === 'High').length;
    const mediumRisk = threatsData.filter(t => t.risk === 'Medium').length;
    const lowRisk = threatsData.filter(t => t.risk === 'Low').length;
    
    document.getElementById('threat-stats').innerHTML = `
        <div class="d-flex justify-content-between mb-3">
            <div>
                <h6 class="mb-0">Total Connections</h6>
                <h3 class="mb-0">${totalThreats}</h3>
            </div>
            <div>
                <h6 class="mb-0">Anomalies</h6>
                <h3 class="mb-0 text-warning">${anomalies}</h3>
            </div>
            <div>
                <h6 class="mb-0">High Risk</h6>
                <h3 class="mb-0 text-danger">${highRisk}</h3>
            </div>
            <div>
                <h6 class="mb-0">Medium Risk</h6>
                <h3 class="mb-0 text-warning">${mediumRisk}</h3>
            </div>
            <div>
                <h6 class="mb-0">Low Risk</h6>
                <h3 class="mb-0 text-success">${lowRisk}</h3>
            </div>
        </div>
    `;
    
    // Display filtered threats
    displayThreats();
}

// Show notification function
function showNotification(title, message) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: message,
            icon: '/static/favicon.ico'
        });
    } else if ('Notification' in window && Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                new Notification(title, {
                    body: message,
                    icon: '/static/favicon.ico'
                });
            }
        });
    }
}

// Add this code to ensure we have form fields for live detection parameters
document.addEventListener('DOMContentLoaded', function() {
    // Add form fields for live detection parameters if they don't exist
    const advancedSettings = document.getElementById('advanced-settings');
    if (advancedSettings) {
        if (!document.getElementById('anomaly-probability')) {
            const row = document.createElement('div');
            row.className = 'row mb-3';
            row.innerHTML = `
                <div class="col-md-6">
                    <label for="anomaly-probability" class="form-label">Anomaly Probability</label>
                    <input type="number" id="anomaly-probability" class="form-control" value="0.2" min="0" max="1" step="0.1">
                </div>
                <div class="col-md-6">
                    <label for="batch-size" class="form-label">Batch Size</label>
                    <input type="number" id="batch-size" class="form-control" value="50" min="10" max="500">
                </div>
            `;
            advancedSettings.appendChild(row);
            
            const row2 = document.createElement('div');
            row2.className = 'row mb-3';
            row2.innerHTML = `
                <div class="col-md-6">
                    <label for="duration" class="form-label">Duration (seconds)</label>
                    <input type="number" id="duration" class="form-control" value="30" min="5" max="300">
                </div>
                <div class="col-md-6">
                    <label for="interval" class="form-label">Interval (seconds)</label>
                    <input type="number" id="interval" class="form-control" value="0.5" min="0.1" max="5" step="0.1">
                </div>
            `;
            advancedSettings.appendChild(row2);
        }
    }
}); 