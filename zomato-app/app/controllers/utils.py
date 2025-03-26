from flask import session

def inject_nav_menu():
    """
    Inject navigation menu items into all templates.
    This is used to build the navigation bar.
    """
    return {
        'nav_items': [
            {'url': '/dashboard', 'title': 'Dashboard'},
            {'url': '/anomaly_detection', 'title': 'Network Anomaly Detection'},
            {'url': '/security', 'title': 'Security Scan'} if session.get('role') == 'admin' else None,
            {'url': '/admin', 'title': 'Admin Panel'} if session.get('role') == 'admin' else None
        ]
    } 