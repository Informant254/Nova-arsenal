# Configuration

Nova-Arsenal is configured through YAML files and environment variables.

## Configuration File

The main configuration file is `settings.yaml`. Copy the example:

```bash
cp config/settings.example.yaml settings.yaml
```

## Configuration Options

### Agent Configuration

```yaml
agent:
  name: "nova-agent"           # Agent name
  version: "1.0.0"             # Version string
  workspace: "/workspace"      # Working directory
  max_steps: 40                # Maximum execution steps
  reflect_every: 5             # Reflection interval
  auto_plan: true              # Auto-generate plans
  auto_visual: true            # Auto-capture visual recon
  auto_cve: true               # Auto-research CVEs
```

### LLM Configuration

```yaml
llm:
  primary:
    provider: "ollama"         # Provider name
    model: "deepseek-r1"       # Model name
    url: "http://llm:11434"    # Provider URL
    api_key: ""                # API key (if required)
    timeout: 120               # Request timeout (seconds)
    
  fallbacks:                   # Fallback providers
    - provider: "openai"
      model: "gpt-4o"
      api_key: "${OPENAI_API_KEY}"
    - provider: "anthropic"
      model: "claude-sonnet-4-20250514"
      api_key: "${ANTHROPIC_API_KEY}"
      
  routing:
    strategy: "cost-optimized" # Routing strategy
    fallback_threshold: 3      # Retries before fallback
    max_retries: 3             # Max retries per provider
```

#### Routing Strategies

- `cost-optimized`: Use cheapest provider first
- `latency-optimized`: Use fastest provider first
- `balanced`: Balance cost and latency

### Security Configuration

```yaml
security:
  permission_profile: "scoped" # read_only, scoped, full
  blocked_patterns:            # Blocked shell patterns
    - "rm -rf /"
    - "curl|bash"
    - "DROP TABLE"
  allowed_tools:               # Allowed tool commands
    - "nmap"
    - "sqlmap"
    - "nuclei"
  blocked_hosts:               # Blocked target hosts
    - "google.com"
    - "facebook.com"
```

### Scope Configuration

```yaml
scope:
  strict_mode: false           # Block out-of-scope targets
  targets:                     # In-scope targets
    - "example.com"
    - "*.example.com"
```

### Logging Configuration

```yaml
logging:
  level: "INFO"                # DEBUG, INFO, WARNING, ERROR
  format: "json"               # json, text
  file: "/workspace/nova.log"  # Log file path
  max_size_mb: 100             # Max log size
  backup_count: 5              # Number of backups
```

### Database Configuration

```yaml
database:
  url: "sqlite+aiosqlite:///workspace/nova.db"
  echo: false                  # Log SQL queries
```

### Authentication Configuration

```yaml
auth:
  jwt_secret: "${JWT_SECRET}"  # JWT signing secret
  access_token_expire_minutes: 15
  refresh_token_expire_days: 7
```

## Environment Variables

All configuration values can be overridden by environment variables:

| Config Path | Environment Variable |
|-------------|---------------------|
| `auth.jwt_secret` | `JWT_SECRET` |
| `database.url` | `DATABASE_URL` |
| `llm.primary.api_key` | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` |
| `logging.level` | `LOG_LEVEL` |

## LiteLLM Configuration

For advanced LLM routing, configure `config/litellm.yaml`:

```yaml
model_list:
  - model_name: "nova-local"
    litellm_params:
      model: "ollama/deepseek-r1"
      api_base: "http://llm:11434"
      
  - model_name: "nova-openai"
    litellm_params:
      model: "gpt-4o"
      api_key: os.environ/OPENAI_API_KEY

litellm_settings:
  num_retries: 3
  request_timeout: 120
  drop_params: true
```

## Docker Configuration

Environment variables can be set in `.env`:

```bash
# LLM API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Authentication
JWT_SECRET=your-secret-here
NEXTAUTH_SECRET=your-secret-here

# Ports
AGENT_PORT=8080
WEB_PORT=3000
LLM_PORT=11434
```

## Kubernetes Configuration

For Kubernetes, use Secrets and ConfigMaps:

```bash
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmap.yaml
```
