CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'user'
);
CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    open_ports INTEGER[],
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    open_ports INTEGER[],
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE network_edges (
    id SERIAL PRIMARY KEY,
    source_device INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    target_device INTEGER REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE graph_metrics (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    degree_centrality FLOAT,
    betweenness_centrality FLOAT,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

