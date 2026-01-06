# CLU Storage & Logging Architecture

This document describes CLU's storage strategy for handling configuration, logs, and analysis results from potentially malicious packages.

## Storage Strategy: Ephemeral with External Integration

CLU uses a **minimal, ephemeral storage approach** optimized for security when analyzing untrusted code:

- **Configuration Files**: Read-only mounts from host (only persistent data)
- **Analysis Results**: Ephemeral (sent to external log aggregators in real-time)
- **Logs**: Sent to stdout/stderr for Docker log drivers and external services
- **Ollama Models**: Named volume (persistent but isolated from analysis data)

**Key principle:** Don't accumulate potentially malicious data on the host filesystem. Results flow directly to your log aggregation system.

## Directory Layout

### Inside Container

```
/home/cluuser/
├── config/                 # Read-only mount from host
│   ├── config.toml        # Application configuration (RO)
│   └── heuristics.toml    # Heuristic rules (RO)
└── .ollama/               # Ollama models (named volume)
```

### On Host

```
./config.toml             # Configuration (checked into git)
./heuristics.toml         # Rules (checked into git)

# No data directory - results go to external systems!
```

## Mount Configuration

### Read-Only Configuration (Only Persistent Mount)

```yaml
volumes:
  - ./config.toml:/home/cluuser/config/config.toml:ro
  - ./heuristics.toml:/home/cluuser/config/heuristics.toml:ro
```

**Why read-only:**
- Prevents container from modifying configuration
- Eliminates risk of malicious code altering analysis rules
- Ensures reproducible behavior across restarts

### Named Volume (Ollama Models Only)

```yaml
volumes:
  # Ollama models only - isolated from analysis data
  - clu-ollama-models:/home/cluuser/.ollama
```

**Why named volume:**
- Models are large (~7GB) and shouldn't pollute host filesystem
- Shared between CLU and Ollama containers
- Persistent across restarts/updates
- No direct host access (additional security layer)

## Logging & Results Integration

All analysis results flow through **logging drivers** to external services:

### 1. Via Webhook (Recommended for Real-Time Alerts)

Configure in `config.toml`:

```toml
[output]
webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Results are posted immediately when detected:

```json
{
  "package_name": "suspicious-package",
  "overall_risk_score": 85,
  "recommendation": "BLOCK",
  "timestamp": "2026-01-06T20:45:00Z"
}
```

### 2. Via Docker Log Drivers (For Centralized Logging)

Configure in `docker-compose.yml`:

#### ELK Stack Example

```yaml
services:
  clu:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "clu.analysis"
```

Then use Filebeat to forward to Elasticsearch:

```yaml
filebeat:
  inputs:
    - type: docker
      containers.ids:
        - clu-scanner
      processors:
        - decode_json_fields:
            fields: ["message"]
            target: ""
```

#### Splunk Example

```yaml
services:
  clu:
    logging:
      driver: "splunk"
      options:
        splunk-token: "${SPLUNK_HEC_TOKEN}"
        splunk-url: "https://splunk.company.com:8088"
        splunk-source: "clu-scanner"
        splunk-sourcetype: "_json"
```

#### CloudWatch Example

```yaml
services:
  clu:
    logging:
      driver: "awslogs"
      options:
        awslogs-group: "/ecs/clu-malware-scanner"
        awslogs-region: "us-east-1"
        awslogs-stream-prefix: "ecs"
```

### 3. Via Fluent Bit (Advanced Multi-Destination)

Forward logs to multiple destinations simultaneously:

```yaml
services:
  clu:
    logging:
      driver: "awsfirelens"
      options:
        awsfirelens-container-name: "fluent-bit"

  fluent-bit:
    image: amazon/aws-for-fluent-bit:latest
    environment:
      - AWS_REGION=us-east-1
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK}
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf
```

## Data Flow: Results Path

```
Container (analysis)
        ↓
    JSON output
        ↓
   stdout/stderr
        ↓
Docker Log Driver
        ↓
   ┌─────────────┬────────────────┬──────────────┐
   ↓             ↓                ↓              ↓
Webhook        Splunk           ELK            CloudWatch
(Slack)        (HEC)            Stack          (CloudWatch)
   ↓             ↓                ↓              ↓
Alert Users   Indexing       Visualization   Metrics/Alarms
```

## Security Benefits

✅ **No persistent malware data** - Results consumed immediately
✅ **Centralized audit trail** - All results in one place (ELK/Splunk)
✅ **Read-only config** - Can't be modified by untrusted code
✅ **Isolated models** - Ollama data separate from analysis
✅ **Automatic cleanup** - Ephemeral container data deleted on stop
✅ **Compliance ready** - External logging for audit/compliance

## Risks & Mitigations

### Risk: Lost Results if No External Service Configured

**Mitigation:** Webhook is mandatory in config
```toml
[output]
webhook = "https://required-endpoint"  # Will error if not set
```

### Risk: External Service Breach

**Mitigation:** Use encrypted endpoints, IAM authentication
```bash
# Secure webhook with API key in env var
webhook = "https://api.example.com/alerts?key=${ALERT_API_KEY}"
```

### Risk: Log Driver Failure

**Mitigation:** Use multiple log drivers simultaneously
```yaml
logging:
  # Primary
  driver: "splunk"
  # Fallback
  - "json-file"  # Always write to container logs too
```

### Risk: Analysis Results Exposure in Transit

**Mitigation:** Use TLS/HTTPS for all external endpoints
```toml
webhook = "https://secure-endpoint.com"  # HTTPS only
```

## Troubleshooting

### Check logs are flowing to external service

```bash
# View container logs
docker logs clu-scanner | tail -20

# Check webhook is working
curl -X POST https://your-webhook \
  -H "Content-Type: application/json" \
  -d '{"test": "webhook"}'
```

### Docker log driver not working

```bash
# Check driver is available
docker info | grep "Logging Driver"

# Check container logs are sent
docker logs --follow clu-scanner

# Verify plugin is loaded for custom drivers
docker plugin ls
```

### No results appearing

```bash
# Check if container is actually analyzing packages
docker logs clu-scanner | grep -i "new package"

# Check webhook endpoint is accessible
docker exec clu-scanner curl -v https://your-webhook

# Check network connectivity
docker exec clu-scanner ping your-log-service.com
```

## Cleanup

Since all data is ephemeral:

```bash
# Stop container - all analysis data is deleted
docker-compose stop

# Remove everything - completely clean slate
docker-compose down

# No need to manage disk space from CLU results
# (Only Ollama models persist, and that's expected)
```

## Comparison: Old vs New Approach

| Aspect | Old (Option B) | New (Ephemeral) |
|--------|---|---|
| Config | RO mount | ✅ RO mount |
| Results | Disk storage | ✅ External service |
| Logs | Disk storage | ✅ Log driver |
| Cleanup | Manual | ✅ Automatic |
| Host Impact | Disk usage grows | ✅ Zero impact |
| Compliance | Manual export | ✅ Integrated |
| Real-time Alerts | Via script | ✅ Webhook |

## Recommended Setup: ELK Stack + Slack

```bash
# 1. Enable webhook in config.toml
[output]
webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK"

# 2. Setup Filebeat to forward Docker logs to Elasticsearch
docker run -d \
  -e ELASTICSEARCH_HOSTS=http://elasticsearch:9200 \
  -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
  docker.elastic.co/beats/filebeat:8.0.0

# 3. View results in Kibana dashboard
# All CLU results automatically indexed and searchable

# 4. Slack notifications for critical findings
# Via webhook in real-time
```

## Related Files

- `docker-compose.yml` - Logging driver configuration
- `Dockerfile` - Minimal, no data directories
- `config.toml` - `[output]` section for webhook configuration
- `.gitignore` - No data directory

---

*Last Updated: 2026-01-06*
