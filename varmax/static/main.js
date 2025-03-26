// Global variables
let threatChart = null;
let currentThreats = [];

// Initialize dashboard when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Update current time
    updateTime();
    setInterval(updateTime, 1000);
    
    // Initialize the threat chart
    initThreatChart();
    
    // Add event listeners
    document.getElementById('test-form').addEventListener('submit', runAnalysis);
    document.getElementById('threat-filter').addEventListener('change', filterThreats);
    document.getElementById('sort-by').addEventListener('change', sortThreats);
    
    // Fetch model info
    fetchModelInfo();
});

// Update the current time display
function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleTimeString();
}

// Initialize the threat distribution chart
function initThreatChart() {
    const ctx = document.getElementById('threat-chart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Normal', 'Anomaly', 'Zero-Day'],
            datasets: [{
                data: [100, 0, 0],
                backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// Run anomaly detection analysis
async function runAnalysis(event) {
    event.preventDefault();
    
    const testDataPath = document.getElementById('test-data-path').value;
    const maxSamples = document.getElementById('max-samples').value;
    const datasetName = document.getElementById('dataset-name').value;
    
    // Show loading state
    document.getElementById('threats-container').innerHTML = `
        <div class="col-12 text-center py-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-3">Analyzing data, please wait...</p>
        </div>
    `;
    
    try {
        const response = await fetch('/api/test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                test_data_path: testDataPath,
                max_samples: parseInt(maxSamples),
                dataset_name: datasetName || null
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            showError(result.error);
            return;
        }
        
        // Display results
        displayResults(result);
    } catch (error) {
        showError('An error occurred while analyzing data: ' + error.message);
    }
}

// Display analysis results
function displayResults(result) {
    // Update threat counts and progress bars
    const normalCount = result.threat_distribution.counts.Normal || 0;
    const anomalyCount = result.threat_distribution.counts.Anomaly || 0;
    const zerodayCount = result.threat_distribution.counts["Zero-Day"] || 0;
    
    document.getElementById('normal-count').textContent = normalCount;
    document.getElementById('anomaly-count').textContent = anomalyCount;
    document.getElementById('zeroday-count').textContent = zerodayCount;
    
    const normalPercent = result.threat_distribution.percentages.Normal || 0;
    const anomalyPercent = result.threat_distribution.percentages.Anomaly || 0;
    const zerodayPercent = result.threat_distribution.percentages["Zero-Day"] || 0;
    
    document.getElementById('normal-progress').style.width = normalPercent + '%';
    document.getElementById('anomaly-progress').style.width = anomalyPercent + '%';
    document.getElementById('zeroday-progress').style.width = zerodayPercent + '%';
    
    // Update threat chart
    threatChart.data.datasets[0].data = [normalPercent, anomalyPercent, zerodayPercent];
    threatChart.update();
    
    // Update risk assessment
    const riskBadge = document.getElementById('risk-badge');
    const riskText = document.getElementById('risk-text');
    
    riskText.textContent = result.risk_assessment || 'Unknown Risk';
    
    if (result.risk_assessment.includes('CRITICAL')) {
        riskBadge.className = 'alert alert-danger';
    } else if (result.risk_assessment.includes('HIGH')) {
        riskBadge.className = 'alert alert-danger';
    } else if (result.risk_assessment.includes('MEDIUM')) {
        riskBadge.className = 'alert alert-warning';
    } else if (result.risk_assessment.includes('ELEVATED')) {
        riskBadge.className = 'alert alert-warning';
    } else {
        riskBadge.className = 'alert alert-success';
    }
    
    // Update analysis info
    document.getElementById('total-records').textContent = result.total_records || '-';
    document.getElementById('analysis-time').textContent = result.analysis_time || '-';
    
    // Store and display threats
    currentThreats = result.detailed_threats || [];
    displayThreats(currentThreats);
}

// Display detected threats
function displayThreats(threats) {
    const container = document.getElementById('threats-container');
    
    if (!threats || threats.length === 0) {
        container.innerHTML = `
            <div class="col-12 text-center py-5">
                <i class="bi bi-shield-check fs-1 text-success"></i>
                <p class="mt-3 text-muted">No threats detected. Your network appears to be secure.</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    
    threats.forEach(threat => {
        // Get top features (limit to 3)
        const features = Object.entries(threat.features || {})
            .slice(0, 3)
            .map(([name, value]) => {
                const percent = Math.min(value * 100, 100).toFixed(0);
                return `
                    <div class="mb-2">
                        <div class="d-flex justify-content-between mb-1">
                            <small>${name}</small>
                            <small>${value.toFixed(4)}</small>
                        </div>
                        <div class="feature-bar">
                            <div class="feature-value" style="width: ${percent}%"></div>
                        </div>
                    </div>
                `;
            })
            .join('');
        
        // Get threat class and badge
        const threatClass = threat.type === 'Zero-Day' ? 'zero-day' : 'anomaly';
        const severityClass = threat.severity === 'HIGH' ? 'severity-high' : 'severity-medium';
        
        html += `
            <div class="col-md-6 fade-in">
                <div class="card threat-card ${threatClass}" data-id="${threat.id}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="mb-0">${threat.type} Threat</h5>
                            <span class="severity-badge ${severityClass}">${threat.severity}</span>
                        </div>
                        <div class="mb-3">
                            <small class="text-muted">ID: ${threat.id} | Confidence: ${threat.confidence}%</small>
                        </div>
                        <h6 class="mb-2">Top Contributing Features:</h6>
                        ${features}
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
    
    // Add click event listener to threat cards for future expansion
    document.querySelectorAll('.threat-card').forEach(card => {
        card.addEventListener('click', () => {
            const threatId = card.getAttribute('data-id');
            showThreatDetails(threatId);
        });
    });
}

// Filter threats based on selected type
function filterThreats() {
    const filterValue = document.getElementById('threat-filter').value;
    const sortBy = document.getElementById('sort-by').value;
    
    let filteredThreats = [...currentThreats];
    
    if (filterValue !== 'all') {
        filteredThreats = filteredThreats.filter(threat => threat.type === filterValue);
    }
    
    sortAndDisplayThreats(filteredThreats, sortBy);
}

// Sort threats based on selected criteria
function sortThreats() {
    const filterValue = document.getElementById('threat-filter').value;
    const sortBy = document.getElementById('sort-by').value;
    
    let filteredThreats = [...currentThreats];
    
    if (filterValue !== 'all') {
        filteredThreats = filteredThreats.filter(threat => threat.type === filterValue);
    }
    
    sortAndDisplayThreats(filteredThreats, sortBy);
}

// Sort and display threats
function sortAndDisplayThreats(threats, sortBy) {
    if (sortBy === 'id') {
        threats.sort((a, b) => a.id - b.id);
    } else if (sortBy === 'confidence') {
        threats.sort((a, b) => b.confidence - a.confidence);
    } else if (sortBy === 'severity') {
        threats.sort((a, b) => {
            const severityOrder = { 'HIGH': 0, 'MEDIUM': 1, 'LOW': 2 };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }
    
    displayThreats(threats);
}

// Show threat details (for future expansion)
function showThreatDetails(threatId) {
    const threat = currentThreats.find(t => t.id == threatId);
    
    if (!threat) return;
    
    // You can implement a modal or detailed view here
    console.log('Selected threat:', threat);
}

// Fetch model information
async function fetchModelInfo() {
    try {
        const response = await fetch('/api/model_info');
        const modelInfo = await response.json();
        
        if (modelInfo.error) return;
        
        // Display KDD info
        const kddInfo = modelInfo.datasets[0];
        document.getElementById('kdd-info').innerHTML = `
            <div><strong>Features:</strong> ${kddInfo.features}</div>
            <div><strong>Classes:</strong> ${kddInfo.classes}</div>
            <div><strong>Distribution:</strong> ${formatDistribution(kddInfo.distribution)}</div>
        `;
        
        // Display Train info
        const trainInfo = modelInfo.datasets[1];
        document.getElementById('train-info').innerHTML = `
            <div><strong>Features:</strong> ${trainInfo.features}</div>
            <div><strong>Classes:</strong> ${trainInfo.classes}</div>
            <div><strong>Distribution:</strong> ${formatDistribution(trainInfo.distribution)}</div>
        `;
        
        // Display UNSW info
        const unswInfo = modelInfo.datasets[2];
        document.getElementById('unsw-info').innerHTML = `
            <div><strong>Features:</strong> ${unswInfo.features}</div>
            <div><strong>Classes:</strong> ${unswInfo.classes}</div>
            <div><strong>Distribution:</strong> ${formatDistribution(unswInfo.distribution)}</div>
        `;
    } catch (error) {
        console.error('Error fetching model info:', error);
    }
}

// Format class distribution for display
function formatDistribution(distribution) {
    if (!distribution) return 'N/A';
    
    return Object.entries(distribution)
        .map(([classId, count]) => `Class ${classId}: ${count}`)
        .join(', ');
}

// Show error message
function showError(message) {
    document.getElementById('threats-container').innerHTML = `
        <div class="col-12 text-center py-5">
            <i class="bi bi-exclamation-triangle fs-1 text-danger"></i>
            <p class="mt-3 text-danger">${message}</p>
        </div>
    `;
} 