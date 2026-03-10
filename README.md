# CyberIntel Platform

**Law-enforcement cyber investigation platform for discovering and mapping criminal infrastructure used in phishing campaigns, scam operations, malware distribution, and fraud networks.**

The system automatically discovers relationships between domains, hosting infrastructure, and websites, then visualizes them as an intelligence graph.

---

## Quick Start

### Prerequisites

- Docker & Docker Compose installed
- At least 4 GB RAM available for containers
- Ports 3000, 7474, 7687, 8000 available

### 1. Clone and start

```bash
git clone <this-repo>
cd cyberintel
docker-compose up --build -d
```

### 2. Wait for services to initialize

```bash
# Watch logs
docker-compose logs -f

# Check health
curl http://localhost:8000/api/health
```

### 3. Open the interfaces

| Service            | URL                          |
|--------------------|------------------------------|
| Investigation UI   | http://localhost:3000         |
| API Docs (Swagger) | http://localhost:8000/docs    |
| Neo4j Browser      | http://localhost:7474         |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     React Frontend                       │
│              Cytoscape.js Graph Viewer                    │
│                  :3000                                    │
└─────────────────────┬───────────────────────────────────┘
                      │ REST API
┌─────────────────────▼───────────────────────────────────┐
│                  FastAPI Backend                          │
│            Artifact Ingestion API                         │
│           Graph Query Endpoints                           │
│         Campaign Detection API                            │
│                  :8000                                    │
└────┬─────────────────┬──────────────────┬───────────────┘
     │                 │                  │
     ▼                 ▼                  ▼
┌─────────┐   ┌──────────────┐   ┌──────────────┐
│  Neo4j  │   │    Redis     │   │  Tor Proxy   │
│  Graph  │   │  + Celery    │   │  (Optional)  │
│  :7687  │   │    :6379     │   │    :9050     │
└─────────┘   └──────┬───────┘   └──────────────┘
                     │
              ┌──────▼───────┐
              │ Celery Worker │
              │              │
              │ • DNS        │
              │ • WHOIS      │
              │ • TLS        │
              │ • Hosting    │
              │ • Playwright │
              │ • Campaign   │
              └──────────────┘
```

---

## Investigation Workflow

### Step 1 — Submit an artifact

**Via UI:** Open http://localhost:3000, select artifact type, enter value, click "Investigate".

**Via API:**

```bash
# Domain investigation
curl -X POST http://localhost:8000/api/artifact \
  -H "Content-Type: application/json" \
  -d '{"type": "domain", "value": "example-login-bank.com", "depth": 2}'

# IP investigation
curl -X POST http://localhost:8000/api/artifact \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "185.234.216.71"}'

# TLS fingerprint search
curl -X POST http://localhost:8000/api/artifact \
  -H "Content-Type: application/json" \
  -d '{"type": "tls_fingerprint", "value": "a1b2c3d4e5f6..."}'
```

### Step 2 — Discovery pipeline executes

The Celery worker automatically:

1. **DNS Resolution** — A, AAAA, MX, NS, TXT, CNAME, SOA records
2. **WHOIS Lookup** — Registrar, creation/expiration dates, nameservers
3. **TLS Certificate** — Fingerprint, issuer, subject, SAN domains
4. **Hosting Data** — IP geolocation, ASN, hosting provider
5. **Website Fingerprint** — HTML structure hash, favicon hash, login form detection, JS libraries, DOM signature, screenshot
6. **Graph Ingestion** — All data stored in Neo4j with relationships
7. **Campaign Analysis** — Auto-clustering of related infrastructure

### Step 3 — Explore the graph

The React UI visualizes the intelligence graph with:
- Color-coded node types (domains, IPs, certificates, etc.)
- Click any node to inspect properties
- Neighborhood highlighting on selection
- Automatic campaign clustering
- Zoom/pan/fit controls

### Step 4 — Review campaigns

The campaign detector links domains that share:
- Same TLS certificate
- Same favicon hash
- Similar HTML structure
- Shared hosting/ASN
- Temporal proximity in registration
- Similar naming patterns

---

## Anonymization Modes

All external requests route through the anonymized networking layer.

| Mode         | Description                              |
|--------------|------------------------------------------|
| `direct`     | No proxy — direct connections            |
| `proxy_chain`| Rotate through a list of proxies         |
| `tor`        | Route through the Tor network            |
| `custom`     | Use a single custom SOCKS/HTTP proxy     |

**Configure via API:**

```bash
# Switch to Tor
curl -X PUT http://localhost:8000/api/network/config \
  -H "Content-Type: application/json" \
  -d '{"mode": "tor", "rate_limit_rps": 1.0, "safe_mode": true}'

# Use custom proxy
curl -X PUT http://localhost:8000/api/network/config \
  -H "Content-Type: application/json" \
  -d '{"mode": "custom", "custom_proxy": "socks5://myproxy:1080"}'
```

All modes include:
- User-Agent randomization
- Configurable rate limiting
- SOCKS proxy support

---

## Neo4j Graph Schema

### Node Types

| Node             | Key Property  | Description                   |
|------------------|---------------|-------------------------------|
| Domain           | name          | Investigated domain           |
| IP               | address       | IPv4/IPv6 address             |
| Certificate      | fingerprint   | TLS certificate SHA-256       |
| FaviconHash      | hash          | MD5 hash of favicon           |
| HTMLFingerprint   | hash          | SHA-256 of HTML structure     |
| ASN              | number        | Autonomous System Number      |
| Registrar        | name          | Domain registrar              |
| HostingProvider   | name          | Hosting company               |
| Campaign         | id            | Detected campaign cluster     |

### Relationships

| Relationship          | From → To                     |
|-----------------------|-------------------------------|
| RESOLVES_TO           | Domain → IP                   |
| USES_CERTIFICATE      | Domain → Certificate          |
| SHARES_FAVICON        | Domain → FaviconHash          |
| SIMILAR_HTML          | Domain → HTMLFingerprint       |
| BELONGS_TO            | IP → ASN                      |
| HOSTED_BY             | IP → HostingProvider           |
| REGISTERED_WITH       | Domain → Registrar            |
| BELONGS_TO_CAMPAIGN   | Domain → Campaign             |

---

## API Reference

| Method | Endpoint                        | Description                      |
|--------|---------------------------------|----------------------------------|
| POST   | /api/artifact                   | Submit artifact for investigation|
| GET    | /api/task/{id}                  | Check task status                |
| GET    | /api/graph                      | Full graph data                  |
| GET    | /api/graph/nodes                | Cytoscape-format graph           |
| GET    | /api/graph/domain/{domain}      | Subgraph around domain           |
| GET    | /api/graph/related/{domain}     | Related domains                  |
| GET    | /api/graph/search?q=            | Search graph nodes               |
| GET    | /api/graph/stats                | Node/edge counts                 |
| GET    | /api/campaigns                  | List campaigns                   |
| POST   | /api/campaigns/detect           | Trigger detection                |
| GET    | /api/campaigns/{id}             | Campaign details                 |
| GET    | /api/network/config             | Current anonymization config     |
| PUT    | /api/network/config             | Update anonymization             |
| GET    | /api/health                     | System health check              |

Interactive API docs at: http://localhost:8000/docs

---

## Offline / Air-gapped Deployment

The platform is designed for secure investigative environments:

1. Build images on a connected machine:
   ```bash
   docker-compose build
   docker save cyberintel-backend cyberintel-frontend > cyberintel-images.tar
   ```

2. Transfer to air-gapped network

3. Load and run:
   ```bash
   docker load < cyberintel-images.tar
   docker-compose up -d
   ```

---

## Project Structure

```
cyberintel/
├── docker-compose.yml
├── .env
├── .gitignore
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py                  # FastAPI application
│       ├── api/
│       │   └── routes.py            # REST endpoints
│       ├── core/
│       │   ├── config.py            # Settings
│       │   ├── database.py          # Neo4j integration
│       │   └── network.py           # Anonymization layer
│       ├── discovery/
│       │   ├── engine.py            # Discovery orchestrator
│       │   ├── dns_collector.py     # DNS resolution
│       │   ├── whois_collector.py   # WHOIS lookups
│       │   ├── tls_collector.py     # TLS certificates
│       │   └── hosting_collector.py # IP/ASN/hosting
│       ├── crawler/
│       │   └── fingerprint.py       # Playwright crawler
│       ├── graph/
│       │   └── engine.py            # Graph relationship engine
│       ├── campaign/
│       │   └── detector.py          # Campaign clustering
│       ├── models/
│       │   └── schemas.py           # Pydantic models
│       └── workers/
│           └── celery_app.py        # Celery tasks
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── index.js
│       ├── App.js                   # Main React app
│       ├── utils/
│       │   └── api.js               # API client
│       └── styles/
│           └── index.css
└── config/
    └── .env.example
```

---

## Troubleshooting

**Neo4j won't start:** Ensure port 7687 is free and you have enough RAM.

**Worker not processing:** Check `docker-compose logs worker` — ensure Redis and Neo4j are healthy.

**Playwright errors:** The worker container includes Chromium. If you see font errors, they're cosmetic and won't affect fingerprinting.

**Rate limiting:** Adjust `RATE_LIMIT_RPS` in config. Default is 2 requests/second to avoid detection.

---

## License

For authorized law-enforcement and security research use only.
