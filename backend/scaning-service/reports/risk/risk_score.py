def calculate_risk_score(cvss, degree, betweenness):
    """
    Risk = CVSS × (Topology Importance)
    """
    return round(cvss * (degree + betweenness + 0.1), 2)

