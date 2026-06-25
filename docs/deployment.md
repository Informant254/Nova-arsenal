# Deployment

This guide covers deploying Nova-Arsenal in various environments.

## Docker Compose (Development)

### Quick Start

```bash
# Clone repository
git clone https://github.com/Informant254/Nova-arsenal.git
cd Nova-arsenal

# Configure environment
cp config/.env.example .env

# Start all services
docker compose up -d

# Check status
docker compose ps
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| web | 3000 | Dashboard |
| agent | 8080 | Agent API |
| llm | 11434 | Ollama LLM |
| sandbox | - | Kali tools |

### Stopping Services

```bash
# Stop services
docker compose down

# Stop and remove volumes
docker compose down -v
```

## Docker Compose (Production)

### Configuration

1. Set secure secrets in `.env`:

```bash
JWT_SECRET=$(openssl rand -base64 32)
NEXTAUTH_SECRET=$(openssl rand -base64 32)
```

2. Use production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Features

- Pre-built images from GHCR
- Resource limits
- Restart policies
- Health checks

## Kubernetes

### Prerequisites

- Kubernetes cluster (1.20+)
- kubectl configured
- Ingress controller (nginx recommended)

### Installation

1. Create namespace:

```bash
kubectl apply -f k8s/namespace.yaml
```

2. Create secrets:

```bash
# Edit k8s/secrets.yaml with your secrets
kubectl apply -f k8s/secrets.yaml
```

3. Apply all manifests:

```bash
kubectl apply -f k8s/
```

4. Check status:

```bash
kubectl get pods -n nova-arsenal
```

### Components

| Component | Replicas | Resources |
|-----------|----------|-----------|
| agent | 1 | 2 CPU, 2Gi |
| web | 1 | 1 CPU, 512Mi |
| llm | 1 | 4 CPU, 8Gi |

### Ingress Configuration

Edit `k8s/ingress.yaml`:

```yaml
spec:
  rules:
    - host: nova.yourdomain.com  # Your domain
```

### TLS/SSL

1. Install cert-manager:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

2. Uncomment TLS section in ingress.yaml

## Cloud Deployment

### AWS (EKS)

```bash
# Configure kubectl for EKS
aws eks update-kubeconfig --name nova-arsenal

# Apply manifests
kubectl apply -f k8s/
```

### Google Cloud (GKE)

```bash
# Configure kubectl for GKE
gcloud container clusters get-credentials nova-arsenal

# Apply manifests
kubectl apply -f k8s/
```

### Azure (AKS)

```bash
# Configure kubectl for AKS
az aks get-credentials --resource-group nova-arsenal --name nova-arsenal

# Apply manifests
kubectl apply -f k8s/
```

## Monitoring

### Health Checks

```bash
# Docker
docker compose ps

# Kubernetes
kubectl get pods -n nova-arsenal
kubectl describe pod <pod-name> -n nova-arsenal
```

### Logs

```bash
# Docker
docker compose logs -f agent
docker compose logs -f web

# Kubernetes
kubectl logs -f deployment/nova-agent -n nova-arsenal
kubectl logs -f deployment/nova-web -n nova-arsenal
```

### Metrics

Prometheus metrics available at:

```
http://localhost:8080/metrics
```

## Backup

### Database

```bash
# Docker
docker compose exec agent cp /workspace/nova.db /workspace/nova.db.bak

# Kubernetes
kubectl exec -it deployment/nova-agent -n nova-arsenal -- cp /workspace/nova.db /workspace/nova.db.bak
```

### Configuration

```bash
# Backup configuration
cp settings.yaml settings.yaml.bak
```

## Scaling

### Horizontal Scaling

```bash
# Kubernetes
kubectl scale deployment/nova-web --replicas=3 -n nova-arsenal
```

### Vertical Scaling

Edit deployment manifests:

```yaml
resources:
  limits:
    memory: "4Gi"  # Increase
    cpu: "4"       # Increase
```

## Troubleshooting

### Pod Not Starting

```bash
kubectl describe pod <pod-name> -n nova-arsenal
kubectl logs <pod-name> -n nova-arsenal
```

### Database Issues

```bash
# Reset database
kubectl exec -it deployment/nova-agent -n nova-arsenal -- rm /workspace/nova.db
kubectl rollout restart deployment/nova-agent -n nova-arsenal
```

### LLM Connection Issues

```bash
# Check Ollama
kubectl logs deployment/nova-llm -n nova-arsenal

# Test connectivity
kubectl exec -it deployment/nova-agent -n nova-arsenal -- curl http://nova-llm:11434/api/tags
```
