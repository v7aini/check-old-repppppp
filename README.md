# CyberSec Platform v8 — Complete Guide

## Quick Start
```bash
cd cybersec-clean
mvn clean spring-boot:run
```
Open: http://localhost:9090/dashboard  
Login: **admin / admin123**

---

## All URLs
| URL | Description |
|-----|-------------|
| http://localhost:9090/dashboard | Main dashboard |
| http://localhost:9090/ids | Intrusion Detection System |
| http://localhost:9090/waf | Web Application Firewall |
| http://localhost:9090/tip | Threat Intelligence |
| http://localhost:9090/network | Network Packet Capture |
| http://localhost:9090/investigate | Investigation Tool |
| http://localhost:9090/swagger-ui.html | API Documentation |
| http://localhost:9090/h2-console | Database Browser |

---

## How to Use Swagger

1. Open http://localhost:9090/swagger-ui.html
2. Find **Authentication** section → click `POST /api/auth/login`
3. Click **Try it out** → use this body:
   ```json
   {"username": "admin", "password": "admin123"}
   ```
4. Click **Execute** → copy the `token` value from the response
5. Click the green **Authorize** button (top of page)
6. In the **BearerAuth** box type:  `Bearer ` then paste your token
7. Click **Authorize** → **Close**
8. All 40+ API endpoints now work — click any, Try it out, Execute

### Test endpoints to try first:
- `GET /api/ids/stats` — alert statistics
- `POST /api/ids/fire-test-alert` — fires a test alert (watch dashboard live)
- `GET /api/network/arp` — all devices on your network with MAC addresses
- `GET /api/waf/blocks/stats` — WAF block statistics
- `POST /api/telegram/test` — test Telegram (after configuring)

---

## How to Test WAF (curl commands)

```bash
# SQLi — should return 403
curl -i --globoff "http://localhost:9090/login?id=1%27%20UNION%20SELECT%20*%20FROM%20users--"

# XSS — should return 403
curl -i "http://localhost:9090/login?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# LFI — should return 403
curl -i "http://localhost:9090/login?file=../../etc/passwd"

# Scanner UA — should return 403
curl -i -A "sqlmap/1.7" http://localhost:9090/dashboard

# Normal request — should return 200 or 302
curl -i http://localhost:9090/login
```

---

## How to Setup Telegram Bot

1. Open Telegram → search **@BotFather** → send `/newbot`
2. Name your bot → copy the **token** (like `123456:ABC-def...`)
3. Start a chat with your bot
4. Visit: `https://api.telegram.org/bot<TOKEN>/getUpdates`
5. Find `"chat":{"id": 987654321}` → copy that number as chat_id
6. Edit `application.properties`:
   ```properties
   telegram.enabled=true
   telegram.bot-token=123456:ABC-def...
   telegram.chat-id=987654321
   ```
7. Restart → test via Swagger: `POST /api/telegram/test`

---

## How to Use Investigation Tool

1. Go to http://localhost:9090/investigate
2. Enter any IP (e.g. `127.0.0.1`) and a reason → click **Investigate →**
3. The tool auto-resolves: MAC address, hostname, alert count, threat score
4. Click **↻ Refresh** to re-resolve
5. Click **Block** → IP is added to WAF + Telegram notification sent
6. Click **Unblock** to remove from WAF
7. Use the **ARP Table** at the bottom to investigate devices on your network

---

## How to Use Network Capture

1. Go to http://localhost:9090/network
2. Capture is ON by default — browse any page to generate packets
3. Packets appear in the live table within 1 second via WebSocket
4. Protocol chart shows HTTP/HTTPS breakdown
5. Top Talkers shows which IPs are most active in the last 30 minutes
6. ARP Table shows all devices visible on your local network

---

## Default Users
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | ADMIN — full access |
| analyst | analyst123 | ANALYST — view + investigate |
| viewer | viewer123 | VIEWER — read only |

---

## Advanced Academic Features (High Value)
- **Java-Powered LSTM Anomaly Detection**: Replaces statistical baselines with a high-performance Java ML engine for temporal traffic analysis (Self-contained, no Python needed).
- **Java NLP Log Summarization**: Uses semantic clustering and K-Means via the Java engine to identify and summarize attack campaigns across all modules.
- **Global Threat Geolocation**: Real-time World Map (Leaflet.js) visualizing the origin of every incoming threat using IP geolocation.
- **SIEM Correlation Engine**: Automatically correlates low-level signals across IDS, WAF, and TIP to detect multi-stage attack patterns.
- **Vulnerability Scanner**: Integrated investigative port scanner with automated CVE mapping for target IPs.
- **Java DDoS CNN Classifier**: Optimized Java CNN emulator for real-time classification of traffic floods (SYN, UDP, HTTP).
- **ML Explainability (XAI)**: Integrated feature importance dashboard for understanding model decisions directly within the Java dashboard.

# cybersec
