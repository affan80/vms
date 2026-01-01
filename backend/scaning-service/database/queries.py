from .db import get_db
import json

def create_user(name, email, password_hash):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO users (name, email, password_hash)
        VALUES (%s, %s, %s)
        RETURNING id, name, email, password_hash, role
        """,
        (name, email, password_hash)
    )

    user = cur.fetchone()
    conn.commit()

    cur.close()
    conn.close()
    return user


def get_user_by_email(email):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, name, email, password_hash, role
        FROM users
        WHERE email = %s
        """,
        (email,)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()
    return user

def get_device(ip, device_type):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id FROM devices WHERE ip_address = %s
    """, (ip,))
    row = cur.fetchone()

    if row:
        device_id = row[0]
    else:
        cur.execute("""
            INSERT INTO devices (ip_address, device_type)
            VALUES (%s, %s)
            RETURNING id
        """, (ip, device_type))
        device_id = cur.fetchone()[0]
        conn.commit()

    cur.close()
    conn.close()
    return device_id


def save_scan_result(device_id, ports):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scan_results (device_id, open_ports)
        VALUES (%s, %s)
    """, (device_id, ports))
    return {
        "scan_id": scan_id,
        "device_id": device_id,
        "open_ports": open_ports,
        "scanned_at": scanned_at
    }
    conn.commit()
    cur.close()
    conn.close()
   

def save_edge(src_id, dst_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO network_edges (source_device, target_device)
        VALUES (%s, %s)
    """, (src_id, dst_id))

    conn.commit()
    cur.close()
    conn.close()


def save_metrics(device_id, degree, betweenness):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO graph_metrics
        (device_id, degree_centrality, betweenness_centrality)
        VALUES (%s, %s, %s)
    """, (device_id, degree, betweenness))

    conn.commit()
    cur.close()
    conn.close()

def save_cve_risk(device_id, service, cve_id, cvss, risk_score):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cve_risks (device_id, service, cve_id, cvss, risk_score)
        VALUES (%s, %s, %s, %s, %s)
    """, (device_id, service, cve_id, cvss, risk_score))
    conn.commit()
    cur.close()
    conn.close()


def save_attack_path(src_id, dst_id, path, probability):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO attack_paths
        (source_device, target_device, path, attack_probability)
        VALUES (%s, %s, %s, %s)
    """, (src_id, dst_id, path, probability))
    conn.commit()
    cur.close()
    conn.close()

