# Docker Quick Start Commands

Quick reference for running vulnerable test applications.

---

## One-Line Starters

### Java - OWASP WebGoat
```bash
docker run -d --name webgoat -p 8080:8080 -p 9090:9090 webgoat/webgoat
# Access: http://localhost:8080/WebGoat
# Register new user to start
```

### PHP - DVWA
```bash
docker run -d --name dvwa -p 80:80 vulnerables/web-dvwa
# Access: http://localhost
# Login: admin / password
# Click "Create / Reset Database" on first run
# Set Security Level to "Low" for testing
```

### PHP - bWAPP
```bash
docker run -d --name bwapp -p 80:80 raesene/bwapp
# Access: http://localhost/install.php first
# Then: http://localhost/login.php
# Login: bee / bug
```

### Node.js - OWASP Juice Shop
```bash
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
# Access: http://localhost:3000
```

### Python - PyGoat
```bash
# No official Docker, use local:
git clone https://github.com/adeyosemanputra/pygoat.git
cd pygoat
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
# Access: http://localhost:8000
```

---

## Start All (For Comprehensive Testing)

```bash
# Start all vulnerable apps
docker run -d --name webgoat -p 8080:8080 webgoat/webgoat
docker run -d --name dvwa -p 80:80 vulnerables/web-dvwa
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
docker run -d --name bwapp -p 8081:80 raesene/bwapp

# Check status
docker ps

# View logs
docker logs webgoat
docker logs dvwa
```

---

## Extract Source Code for Scanning

Semgrep scans source code, not running apps. Extract from containers:

```bash
# WebGoat (Java)
docker cp webgoat:/home/webgoat/webgoat /tmp/webgoat-src
semgrep --config rule.yaml /tmp/webgoat-src/

# DVWA (PHP)
docker cp dvwa:/var/www/html /tmp/dvwa-src
semgrep --config rule.yaml /tmp/dvwa-src/

# Juice Shop (Node.js)
docker cp juiceshop:/juice-shop /tmp/juiceshop-src
semgrep --config rule.yaml /tmp/juiceshop-src/
```

---

## Clone for Better Analysis

For full git history and test isolation:

```bash
# WebGoat
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat
semgrep --config ../custom-rules/cve/rule.yaml .

# DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA
semgrep --config ../custom-rules/cve/rule.yaml .

# Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
semgrep --config ../custom-rules/cve/rule.yaml .

# NodeGoat
git clone https://github.com/OWASP/NodeGoat.git
cd NodeGoat
semgrep --config ../custom-rules/cve/rule.yaml .

# RailsGoat
git clone https://github.com/OWASP/railsgoat.git
cd railsgoat
semgrep --config ../custom-rules/cve/rule.yaml .
```

---

## Stop and Cleanup

```bash
# Stop all
docker stop webgoat dvwa juiceshop bwapp

# Remove containers
docker rm webgoat dvwa juiceshop bwapp

# Remove images (to save space)
docker rmi webgoat/webgoat vulnerables/web-dvwa bkimminich/juice-shop raesene/bwapp
```

---

## Port Reference

| App | Port | URL |
|-----|------|-----|
| WebGoat | 8080 | http://localhost:8080/WebGoat |
| WebWolf | 9090 | http://localhost:9090/WebWolf |
| DVWA | 80 | http://localhost |
| bWAPP | 80/8081 | http://localhost:8081 |
| Juice Shop | 3000 | http://localhost:3000 |

---

## Running Semgrep Against Docker Volumes

If you need to scan without extracting:

```bash
# Create volume with source
docker run -d --name webgoat -p 8080:8080 \
  -v webgoat-src:/home/webgoat/webgoat \
  webgoat/webgoat

# Run semgrep with volume mount
docker run --rm \
  -v webgoat-src:/src \
  -v $(pwd)/custom-rules:/rules \
  returntocorp/semgrep \
  semgrep --config /rules/cve/rule.yaml /src
```

---

## OWASP Benchmark (Standardized Testing)

```bash
# Clone (no Docker available)
git clone https://github.com/OWASP/Benchmark.git
cd Benchmark

# Build
./mvnw compile

# Scan
semgrep --config ../custom-rules/ src/main/java/ --json > results.json

# Compare to expected results
# Ground truth in: expectedresults-X.Y.csv
```

---

## Troubleshooting

### Container won't start
```bash
# Check if port is in use
lsof -i :8080
# Kill conflicting process or use different port
docker run -p 8081:8080 webgoat/webgoat
```

### Out of disk space
```bash
# Clean up Docker
docker system prune -a
```

### Permission denied on extracted files
```bash
# Fix permissions
sudo chown -R $(whoami) /tmp/dvwa-src
```
