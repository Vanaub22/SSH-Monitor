# Remote Dashboard Access Guide

This guide explains how to make your SSH-Monitor dashboard accessible to others on different systems over the internet.

---

## Quick Comparison

| Method | Setup Time | Cost | Public URL | Best For |
|--------|-----------|------|-----------|----------|
| **Cloudflare Tunnel** | 5 min | Free | Yes | 24/7 permanent access |
| **ngrok** | 2 min | Free (temp URL) | Yes | Quick temporary sharing |
| **GitHub Pages** | 30 min | Free | Yes | Static snapshots only (not real-time) |
| **Cloud Deploy (Render)** | 20 min | Free tier | Yes | Fully remote setup |

---

## Option 1: Cloudflare Tunnel (Recommended ⭐)

**Best for:** Permanent 24/7 remote access, no cost, simple setup

### Setup (5 minutes)

#### Step 1: Create Free Cloudflare Account
1. Go to [cloudflare.com](https://www.cloudflare.com)
2. Sign up for free account
3. Verify email

#### Step 2: Install cloudflared

**macOS:**
```bash
brew install cloudflare/cloudflare/cloudflared
```

**Linux:**
```bash
curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64.tgz | tar xz
sudo mv ./cloudflared /usr/local/bin
```

#### Step 3: Authenticate

```bash
cloudflared login
# Opens browser to authorize access
# Creates ~/.cloudflare/cert.pem
```

#### Step 4: Start Dashboard & Tunnel

Terminal 1 - Start deployment:
```bash
./scripts/deploy.sh
```

Terminal 2 - Start tunnel:
```bash
./scripts/expose-tunnel.sh
```

#### Step 5: Get Public URL

```bash
cloudflared tunnel list
```

You'll see something like:
```
NAME                        ID                                     NAME
ssh-monitor-dashboard       a1b2c3d4-e5f6-7890...                 my-dashboard.mydomain.workers.dev
```

**Share this URL with anyone:** `https://my-dashboard.mydomain.workers.dev`

### How It Works

```
Your Computer                    Internet                   Internet Users
┌──────────────────┐            ┌─────────┐               ┌──────────────┐
│  Grafana         │◄───────────┤Cloudflare   ├──────────►│  Browser     │
│  :3000           │  Tunnel    │  Tunnel     │  HTTPS    │  Anywhere    │
└──────────────────┘            └─────────┘               └──────────────┘
```

### Pros
- ✓ Free forever
- ✓ No port forwarding needed
- ✓ Automatic HTTPS
- ✓ No credit card required
- ✓ Permanent URL with free tier

### Cons
- ✗ Requires Cloudflare account
- ✗ Depends on Cloudflare uptime

### Advanced: Custom Domain

To use your own domain (optional):

1. Move domain to Cloudflare nameservers (10 minutes)
2. Set CNAME record in Cloudflare DNS
3. Use permanent custom URL like `dashboard.yourdomain.com`

---

## Option 2: ngrok (Quick Sharing)

**Best for:** Quick demos and temporary access (< 1 hour)

### Setup (2 minutes)

#### Step 1: Create Free Account
- Go to [ngrok.com](https://ngrok.com)
- Sign up for free
- Get authtoken from dashboard

#### Step 2: Install ngrok

**macOS:**
```bash
brew install ngrok
```

**Linux/Manual:**
- Download from [ngrok.com/download](https://ngrok.com/download)

#### Step 3: Configure & Run

```bash
# Add your auth token
ngrok config add-authtoken YOUR_TOKEN_HERE

# Start Grafana
./scripts/deploy.sh

# In another terminal, expose it
./scripts/expose-ngrok.sh
```

You'll see output like:
```
Session Status                online
Account                       your-email@example.com
Version                       3.0.5
Forwarding                    https://abc123-456def.ngrok.io -> http://localhost:3000
```

**Share this URL:** `https://abc123-456def.ngrok.io`

### Pros
- ✓ Super fast setup
- ✓ Free tier available
- ✓ Works immediately

### Cons
- ✗ Free tier: URL changes every run
- ✗ Free tier: Sessions expire after ~2 hours
- ✗ Paid ($5-15/month) for permanent URLs
- ✗ Rate limits on free tier

---

## Option 3: GitHub Pages (Static Snapshots)

**Best for:** Sharing reports and historical dashboards (not real-time)

### How It Works

Export Grafana dashboard as JSON → Push to GitHub Pages → View as static HTML

### Setup

#### Step 1: Create Repository

```bash
# Create GitHub repo named: ssh-monitor-dashboard
git clone https://github.com/YOUR_USERNAME/ssh-monitor-dashboard
cd ssh-monitor-dashboard
```

#### Step 2: Export Grafana Dashboard

1. Open Grafana at `http://localhost:3000`
2. Click dashboard name → Settings
3. Click "JSON Model"
4. Copy entire JSON
5. Save as `dashboard.json`

#### Step 3: Create HTML Viewer

Create `index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>SSH-Monitor Dashboard</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        h1 { color: #333; }
        .info { background: #f0f0f0; padding: 10px; margin: 10px 0; }
        pre { background: #f9f9f9; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>SSH-Monitor Dashboard Report</h1>
    <div class="info">
        <p>Generated: <span id="date"></span></p>
        <p>This is a static snapshot of the SSH-Monitor dashboard.</p>
        <p>For live monitoring, use the tunnel setup instead.</p>
    </div>
    <h2>Dashboard Configuration</h2>
    <pre id="dashboard"></pre>
    
    <script>
        document.getElementById('date').textContent = new Date().toLocaleString();
        fetch('dashboard.json')
            .then(r => r.json())
            .then(data => {
                document.getElementById('dashboard').textContent = 
                    JSON.stringify(data, null, 2);
            });
    </script>
</body>
</html>
```

#### Step 4: Push to GitHub

```bash
git add index.html dashboard.json
git commit -m "Add SSH-Monitor dashboard"
git push origin main
```

#### Step 5: Enable GitHub Pages

1. Go to GitHub repository settings
2. Scroll to "GitHub Pages"
3. Set source to "main" branch
4. Save

View at: `https://YOUR_USERNAME.github.io/ssh-monitor-dashboard`

### Pros
- ✓ Completely free
- ✓ GitHub automatically hosts it
- ✓ Good for sharing reports

### Cons
- ✗ Not real-time (static snapshot)
- ✗ No live metrics
- ✗ Need to manually export and push updates

---

## Option 4: Cloud Deployment (Render.com)

**Best for:** Full remote setup without local services running

This deploys Prometheus + Grafana to Render cloud. The C++ parser still runs locally but sends data to cloud.

### Architecture

```
Local System                  Cloud (Render)
┌──────────────────┐         ┌───────────────────┐
│ C++ Parser       │         │ Prometheus        │
└────────┬─────────┘         └─────────┬─────────┘
         │                            │
         └────► Python Exporter ◄─────┘
                     ▲
                     │ (pushes metrics)
                     │
              ┌──────▼────────┐
              │  Grafana      │
              │  (on Render)  │
              └───────────────┘
```

### Setup (20 minutes)

#### Step 1: Prepare Cloud Docker Compose

Create `docker-compose-cloud.yml`:

```yaml
version: '3'

services:
  prometheus:
    image: prom/prometheus:v2.51.0
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    environment:
      - SCRAPE_INTERVAL=15s
      - EXPORTER_URL=http://YOUR_LOCAL_IP:9101/metrics
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=7d"

  grafana:
    image: grafana/grafana:10.4.0
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH: /var/lib/grafana/dashboards/ssh_monitoring.json
    volumes:
      - ./grafana/provisioning/datasources:/etc/grafana/provisioning/datasources:ro
      - ./grafana/provisioning/dashboards:/var/lib/grafana/dashboards:ro
      - grafana-data:/var/lib/grafana

volumes:
  prometheus-data:
  grafana-data:
```

#### Step 2: Deploy to Render

1. Create GitHub repository with project
2. Go to [render.com](https://render.com)
3. Sign up (free)
4. Create new "Web Service"
5. Connect GitHub repository
6. Set start command: `docker-compose up`
7. Deploy

#### Step 3: Configure Local Parser

Update local prometheus to scrape cloud instance:

```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ssh-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9101']  # Local exporter
```

Then push metrics from cloud Prometheus to local exporter.

### Pros
- ✓ Fully automated deployment
- ✓ Scales easily
- ✓ Professional setup

### Cons
- ✗ Complex configuration
- ✗ Free tier has limitations
- ✗ Need to publish IP/address

---

## Comparison Table - Real Scenarios

### Scenario 1: Share with Team for 1 Hour Demo

**Best:** ngrok

```bash
./scripts/deploy.sh
./scripts/expose-ngrok.sh
# Share URL with team
# Done in 2 minutes
```

### Scenario 2: 24/7 Dashboard - Remote Monitoring

**Best:** Cloudflare Tunnel

```bash
./scripts/deploy.sh
./scripts/expose-tunnel.sh
# Permanent URL - check any time
# Runs forever for free
```

### Scenario 3: Build Historical Reports - Share Weekly

**Best:** GitHub Pages

```bash
# Export dashboard monthly
# Push to GitHub Pages
# Share snapshots
```

### Scenario 4: Run Dashboard in Cloud - No Local Services

**Best:** Render + Local Exporter Push

- Complex but fully cloud-hosted
- Free tier suitable for testing

---

## Security Considerations

### ⚠️ Important

Your dashboard logs SSH attacks. Before exposing to internet:

1. **Change Grafana Password**
   ```bash
   curl -X PUT http://admin:admin@localhost:3000/api/user/password \
     -H "Content-Type: application/json" \
     -d '{"oldPassword":"admin","newPassword":"YOUR_STRONG_PASSWORD"}'
   ```

2. **Use HTTPS** (Cloudflare Tunnel & ngrok both use HTTPS automatically)

3. **Share URLs Carefully** (only with trusted people)

4. **Add IP Whitelist** (premium ngrok feature)

5. **Monitor Access**
   - Cloudflare: Check tunnel analytics
   - ngrok: Review session logs
   - Grafana: Check auth logs

---

## Troubleshooting

### Cloudflare Tunnel Issues

**URL not showing up:**
```bash
# Verify tunnel is running
cloudflared tunnel list

# Check tunnel status
cloudflared tunnel info ssh-monitor-dashboard

# View logs
cloudflared tunnel run ssh-monitor-dashboard --loglevel debug
```

**Connection refused:**
- Make sure Grafana is running: `./scripts/monitor.sh`
- Check URL: should be `http://localhost:3000` (not HTTPS)

### ngrok Issues

**Can't connect:**
```bash
# Verify auth token is set
ngrok config list

# Add token if missing
ngrok config add-authtoken YOUR_TOKEN_HERE

# Try again
./scripts/expose-ngrok.sh
```

**Session expired:**
- Free tier sessions last ~2 hours
- Either keep terminal open or upgrade to paid

### GitHub Pages Issues

**Page not showing:**
- Wait 1-2 minutes after push (GitHub needs time)
- Check branch is "main" in settings
- Check files are committed (not just staged)

---

## Recommended Setup

```bash
# 1. Start local dashboard
./scripts/deploy.sh

# 2. Expose with Cloudflare Tunnel (permanent + free)
./scripts/expose-tunnel.sh

# 3. Get public URL
cloudflared tunnel list

# 4. Share URL with others
https://my-dashboard.workers.dev
```

Anyone anywhere can now view your real-time SSH monitoring dashboard! 🎯

---

## Next Steps

- [Cloudflare Tunnel Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [ngrok Documentation](https://ngrok.com/docs)
- [Render Deployment Guide](https://render.com/docs)
- [GitHub Pages](https://pages.github.com)
