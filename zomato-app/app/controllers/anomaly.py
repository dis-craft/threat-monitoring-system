from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
import os
import threading
from datetime import datetime
from app.services.anomaly_detection.detector import start_anomaly_detection, get_latest_anomalies
import requests
import logging

anomaly_bp = Blueprint('anomaly', __name__)

# Global variable for anomaly detection status
anomaly_detection_status = {
    'running': False,
    'progress': 0,
    'high_risk_count': 0,
    'medium_risk_count': 0,
    'low_risk_count': 0
}

@anomaly_bp.route('/anomaly_detection')
def anomaly_detection_dashboard():
    """
    Display the network anomaly detection dashboard.
    This is integrated with the KDD dataset for real-time simulation.
    """
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    return render_template('anomaly_dashboard.html')

@anomaly_bp.route('/anomaly_detection/start', methods=['POST'])
def start_anomaly_detection_route():
    """
    Start the anomaly detection process with the selected dataset.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get parameters from form
    dataset = request.form.get('dataset', 'kdd_test')
    batch_size = int(request.form.get('batch_size', 100))
    sleep_interval = int(request.form.get('sleep_interval', 5))
    
    # Determine dataset path
    if dataset == 'kdd_train':
        dataset_path = os.path.join('data_kdd', 'kdd_train.csv')
    else:
        dataset_path = os.path.join('data_kdd', 'kdd_test.csv')
    
    # Start detection
    success = start_anomaly_detection(dataset_path)
    
    # Store detection status
    global anomaly_detection_status
    anomaly_detection_status = {
        'running': success,
        'dataset': dataset,
        'batch_size': batch_size,
        'sleep_interval': sleep_interval,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'progress': 0,
        'high_risk_count': 0,
        'medium_risk_count': 0,
        'low_risk_count': 0
    }
    
    return jsonify({'success': success, 'error': None if success else 'Failed to start detection'})

@anomaly_bp.route('/anomaly_detection/stop', methods=['POST'])
def stop_anomaly_detection():
    """
    Stop the anomaly detection process.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    global anomaly_detection_status
    anomaly_detection_status['running'] = False
    
    return jsonify({'success': True})

@anomaly_bp.route('/anomaly_detection/updates')
def get_anomaly_updates():
    """
    Get updates on anomaly detection progress and new anomalies.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    # Get latest anomalies from the queue
    anomalies = get_latest_anomalies(max_items=10)
    
    global anomaly_detection_status
    
    # Update counters based on new anomalies
    for anomaly in anomalies:
        if anomaly.get('highest_confidence', 0) >= 0.9:
            anomaly_detection_status['high_risk_count'] += 1
        elif anomaly.get('highest_confidence', 0) >= 0.7:
            anomaly_detection_status['medium_risk_count'] += 1
        else:
            anomaly_detection_status['low_risk_count'] += 1
    
    # Increment progress (simulate progress)
    if anomaly_detection_status.get('running', False):
        anomaly_detection_status['progress'] += 1
        if anomaly_detection_status['progress'] > 100:
            anomaly_detection_status['progress'] = 0
    
    # Prepare response
    response = {
        'success': True,
        'status': 'Running' if anomaly_detection_status.get('running', False) else 'Stopped',
        'progress': anomaly_detection_status.get('progress', 0),
        'high_risk_count': anomaly_detection_status.get('high_risk_count', 0),
        'medium_risk_count': anomaly_detection_status.get('medium_risk_count', 0),
        'low_risk_count': anomaly_detection_status.get('low_risk_count', 0),
        'anomalies': [
            {
                'timestamp': a.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'protocol_type': a.get('protocol_type', 'unknown'),
                'service': a.get('service', 'unknown'),
                'flag': a.get('flag', 'unknown'),
                'alert_types': a.get('alert_types', ''),
                'highest_confidence': a.get('highest_confidence', 0)
            } for a in anomalies
        ]
    }
    
    return jsonify(response)

@anomaly_bp.route('/anomaly_detection/report_threat', methods=['POST'])
def report_threat():
    """
    Report a detected threat to the Zero Day Sentinel service.
    First verifies if the threat already exists in the blockchain.
    Skips posting if attack_type is unknown.
    """
    # Set up logging
    logger = logging.getLogger('anomaly_controller')
    logger.setLevel(logging.INFO)
    
    if not session.get('logged_in'):
        logger.warning('Unauthorized attempt to report threat - user not logged in')
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    try:
        threat_data = request.json
        threat_id = threat_data.get('id')
        attack_type = threat_data.get('attack_type', 'unknown')
        
        logger.info(f'Processing threat report - ID: {threat_id}, Attack Type: {attack_type}')
        
        # Skip if attack type is unknown
        if attack_type.lower() == 'unknown':
            logger.info(f'Skipping threat {threat_id} - Attack type is unknown')
            return jsonify({
                'success': False,
                'error': 'Cannot report threat with unknown attack type',
                'threat_id': threat_id
            })
        
        # First check if threat exists in blockchain
        logger.info(f'Checking if threat {threat_id} exists in blockchain')
        chain_response = requests.get(
            'https://zero-day-sentinel.onrender.com/chain',
            timeout=10
        )
        
        if chain_response.status_code == 200:
            blockchain_data = chain_response.json()
            logger.info(f'Successfully retrieved blockchain data - {len(blockchain_data)} blocks')
            
            # Check if threat already exists
            for block in blockchain_data:
                if 'transactions' in block:
                    for transaction in block['transactions']:
                        if transaction.get('id') == threat_id:
                            logger.info(f'Threat {threat_id} already exists in blockchain')
                            return jsonify({
                                'success': False,
                                'error': 'Threat already exists in blockchain',
                                'threat_id': threat_id
                            })
            
            # If threat doesn't exist and attack type is known, post it
            logger.info(f'Posting new threat {threat_id} to Zero Day Sentinel')
            response = requests.post(
                'https://zero-day-sentinel.onrender.com/threat',
                json=threat_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f'Successfully reported threat {threat_id}')
                return jsonify({
                    'success': True, 
                    'message': 'Threat reported successfully',
                    'response': response.json() if response.content else None,
                    'threat_id': threat_id
                })
            else:
                logger.error(f'Failed to report threat {threat_id} - HTTP {response.status_code}')
                logger.error(f'Response: {response.text}')
                return jsonify({
                    'success': False,
                    'error': f'Failed to report threat: HTTP {response.status_code}',
                    'response': response.text
                })
        else:
            logger.error(f'Failed to check blockchain - HTTP {chain_response.status_code}')
            logger.error(f'Response: {chain_response.text}')
            return jsonify({
                'success': False,
                'error': f'Failed to check blockchain: HTTP {chain_response.status_code}',
                'response': chain_response.text
            })
    
    except Exception as e:
        logger.error(f'Error processing threat {threat_id if "threat_id" in locals() else "unknown"}: {str(e)}')
        return jsonify({
            'success': False,
            'error': f'Error reporting threat: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/verify_threat', methods=['GET'])
def verify_threat():
    """
    Verify if a reported threat exists in the Zero Day Sentinel blockchain.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    threat_id = request.args.get('threat_id')
    if not threat_id:
        return jsonify({'success': False, 'error': 'No threat ID provided'})
    
    try:
        # Fetch the blockchain data
        response = requests.get(
            'https://zero-day-sentinel.onrender.com/chain',
            timeout=10
        )
        
        if response.status_code == 200:
            blockchain_data = response.json()
            
            # Look for the threat in the blockchain
            found = False
            block_index = -1
            
            for i, block in enumerate(blockchain_data):
                if 'transactions' in block:
                    for transaction in block['transactions']:
                        if transaction.get('id') == threat_id:
                            found = True
                            block_index = i
                            break
                    if found:
                        break
            
            return jsonify({
                'success': True,
                'found': found,
                'block_index': block_index if found else -1
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch blockchain: HTTP {response.status_code}',
                'response': response.text
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error verifying threat: {str(e)}'
        })

@anomaly_bp.route('/anomaly_detection/blockchain', methods=['GET'])
def get_blockchain():
    """
    Get the latest blockchain data from Zero Day Sentinel.
    """
    if not session.get('logged_in'):
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    try:
        # Fetch the blockchain data
        response = requests.get(
            'https://zero-day-sentinel.onrender.com/chain',
            timeout=10
        )
        
        if response.status_code == 200:
            blockchain_data = response.json()
            
            # Extract threats from blockchain
            threats = []
            for block in blockchain_data:
                if 'transactions' in block:
                    for transaction in block['transactions']:
                        threats.append(transaction)
            
            return jsonify({
                'success': True,
                'threats': threats,
                'blockchain': blockchain_data
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to fetch blockchain: HTTP {response.status_code}',
                'response': response.text
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching blockchain: {str(e)}'
        }) 