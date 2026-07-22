# Holepunch

Deployment chart for the Holepunch project.

## Required Secrets:

The deployment requires that several secrets be manually established in advance
of running any Helm commands:

* `nats-auth`: Used 
  - `username`/`password`: Credentials used by Holepunch to access/modify all stores and subscriptions.

* `holepunch-secrets`: Mounted as environment variables into Holepunch deployments.
  - `HOLEPUNCH_NATS_HOST`: Required to access our NATS instance (e.g., `nats://user:pass@holepunch.namespace.svc.cluster.local:4222`)
