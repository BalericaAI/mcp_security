# Introduction to MCP Servers and Their Role in Kubernetes Clusters

## What Is MCP?

The Model Context Protocol (MCP) is an open standard, originally introduced by Anthropic, that defines a common way for AI applications (the "client" or "host," such as an LLM-powered assistant or IDE plugin) to connect to external tools, data sources, and systems (the "server"). Instead of every AI application writing custom, one-off integrations for every tool it needs to use, MCP servers expose a standardized set of capabilities — tools (actions the model can invoke), resources (data the model can read), and prompts (reusable templates) — over a shared protocol.

In practice, an MCP server is a small service that wraps an existing system (a database, a SaaS API, a cloud platform, or in this case, a Kubernetes cluster) and translates natural-language intent from an AI agent into concrete API calls against that system, then returns structured results back to the model.

## Transport Models

MCP supports two primary transport mechanisms, which matter a lot when deciding how to run a server in Kubernetes:

- **stdio**: the server runs as a local subprocess and communicates over standard input/output. This is common for local development or single-user desktop tools, but doesn't fit a clustered, multi-tenant environment.
- **Streamable HTTP**: the server runs as a standalone HTTP service, using POST for requests and Server-Sent Events (SSE) for streaming responses. This is the transport that matters for Kubernetes — it lets an MCP server be deployed like any other network service, sit behind a load balancer, and scale horizontally.

For a class covering cloud and platform engineering, the practical takeaway is: local/stdio MCP servers are processes; remote/HTTP MCP servers are services — and services are what you deploy to a cluster.

## Why Run MCP Servers on Kubernetes

Once an MCP server uses the Streamable HTTP transport, it behaves like any other stateless (or mostly stateless) microservice, which makes Kubernetes a natural fit:

- **Scaling**: MCP servers can be run in stateless mode (no persisted session state between requests), which allows a Horizontal Pod Autoscaler to add or remove replicas based on load, the same as any REST API.
- **Availability**: standard Kubernetes primitives — readiness/liveness probes, rolling updates, pod disruption budgets — give MCP servers the same resiliency guarantees as other production services.
- **Isolation and multi-tenancy**: separate MCP server deployments (or namespaces) can be scoped to different clusters or environments — for example, one MCP server with read-only access to a staging cluster, and a separate, more tightly scoped one for production.
- **Multi-cluster access**: an MCP server that wraps the Kubernetes API itself (e.g. exposing tools like "list pods," "get logs," "scale deployment") can be configured to talk to multiple clusters — dev, staging, production — through separate kubeconfig contexts, letting an AI agent operate across environments through one consistent interface.

A concrete example already in the wild: the open-source `kubernetes-mcp-server` project exposes Kubernetes/OpenShift cluster operations (listing resources, fetching logs, managing Helm releases) as MCP tools, so an AI agent can be asked to "show me pods crash-looping in the payments namespace" and have that translated into real `kubectl`-equivalent API calls.

## Security Considerations

This is the piece most worth emphasizing for a security-focused audience, because an MCP server that talks to a Kubernetes API is effectively a new, potentially very privileged, identity in the cluster:

- **Authentication/authorization**: for any remote (HTTP) MCP server, MCP specifies an authorization model built on OAuth 2.1 — the AI client acts as an OAuth client, requests a scoped access token from an authorization server, and presents it as a bearer token on every request. The MCP server validates the token and its scopes before executing any tool call. HTTPS is mandatory for any HTTP-based deployment.
- **Least privilege**: best practice is to start any new MCP server integration with read-only permissions and expand scope deliberately — this maps directly onto Kubernetes RBAC, where the MCP server's service account should be bound to the narrowest role that satisfies its use case (e.g., `get`/`list` on pods and logs, not cluster-admin).
- **Network boundaries**: MCP servers that expose cluster operations should sit behind the same network policies, ingress controls, and mTLS expectations as any other sensitive internal API — not left open on a NodePort.
- **Observability**: integrating OpenTelemetry (or equivalent tracing/logging) with the MCP server gives security and platform teams an audit trail of exactly which tools an AI agent invoked, with what arguments, and against which cluster resources — important both for incident response and for catching an agent doing something it shouldn't.
- **Secrets management**: kubeconfig credentials, API tokens, or service account tokens the MCP server uses to reach the cluster(s) it manages should be handled the same way as any other cluster secret (e.g., mounted via Kubernetes Secrets or an external secrets manager), not baked into the container image.

## Summary for the Class

MCP servers are the connective tissue between AI agents and real infrastructure. When that infrastructure is Kubernetes, the MCP server itself becomes just another workload to deploy, scale, and secure — but one worth treating carefully, since its entire purpose is to let a model take real actions against your cluster. The interesting engineering and security questions aren't about MCP as a novel technology so much as applying familiar platform engineering discipline (RBAC, least privilege, observability, network policy) to a new kind of client: an AI agent instead of a human operator or CI pipeline.

---

Sources:
- [18 Best DevOps MCP Servers for 2026 — Medium/k8slens](https://medium.com/k8slens/18-best-devops-mcp-servers-for-2026-the-definitive-guide-bfde04654a35)
- [kubernetes-mcp-server (GitHub)](https://github.com/containers/kubernetes-mcp-server)
- [MCP Best Practices — modelcontextprotocol.info](https://modelcontextprotocol.info/docs/best-practices/)
- [Understanding Authorization in MCP — modelcontextprotocol.io](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [OAuth 2.1 for Remote MCP Servers — MCP.Directory](https://mcp.directory/blog/oauth-21-for-remote-mcp-servers-streamable-http-explained-2026)
