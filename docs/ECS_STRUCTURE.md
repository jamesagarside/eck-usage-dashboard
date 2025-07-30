# ECK Usage Monitor - ECS Compliant Structure

## Overview

The ECK Usage Monitor now generates **Elastic Common Schema (ECS) compliant** documents and creates **individual documents for each deployment sub-component**. This provides granular visibility into resource usage at the component instance level.

## Document Structure

### Example Scenario

For an Elasticsearch deployment named "production" with:

- 3 hot nodes (nodeset: "hot")
- 3 cold nodes (nodeset: "cold")
- 2 frozen nodes (nodeset: "frozen")
- 2 Kibana instances

**Result**: 10 individual documents (8 for Elasticsearch node sets + 2 for Kibana instances)

### ECS Fields Used

#### Core ECS Fields

- `@timestamp` - Document creation timestamp
- `ecs.version` - ECS schema version (8.0.0)
- `event.*` - Event metadata (kind: metric, category: host, etc.)

#### Orchestrator Fields (ECS Orchestrator Schema)

- `orchestrator.type` - "kubernetes"
- `orchestrator.namespace` - Kubernetes namespace
- `orchestrator.resource.name` - Component instance name (e.g., "production-hot")
- `orchestrator.resource.type` - Component type (e.g., "elasticsearch-nodeset")
- `orchestrator.resource.id` - Kubernetes UID
- `orchestrator.cluster.name` - Kubernetes cluster name
- `orchestrator.cluster.version` - Kubernetes version

#### Service Fields

- `service.name` - Service instance name (e.g., "elasticsearch-hot")
- `service.type` - Component type (elasticsearch, kibana, apm, etc.)
- `service.version` - Elastic Stack version

#### Host Fields

- `host.name` - Host/component instance name
- `host.type` - Type of host/component
- `host.architecture` - Architecture (default: x86_64)
- `host.containerized` - Always true for ECK components

### Custom ECK Fields

#### Deployment Information (`eck.deployment.*`)

- `eck.deployment.name` - ECK deployment name
- `eck.deployment.namespace` - Kubernetes namespace
- `eck.deployment.created` - Creation timestamp
- `eck.deployment.uid` - Kubernetes UID
- `eck.deployment.generation` - Resource generation
- `eck.deployment.labels` - Kubernetes labels
- `eck.deployment.annotations` - Kubernetes annotations

#### Component Information (`eck.component.*`)

- `eck.component.type` - Specific component type (e.g., "elasticsearch-nodeset", "kibana-instance")
- `eck.component.instance_name` - Instance name within deployment
- `eck.component.instance_number` - Instance number (for multi-instance components)
- `eck.component.node_count` - Number of nodes (for Elasticsearch node sets)
- `eck.component.roles` - Node roles (for Elasticsearch)
- `eck.component.parent_deployment` - Parent deployment name

#### Status Information (`eck.status.*`)

- `eck.status.health` - Component health (green, yellow, red)
- `eck.status.phase` - Component phase (Ready, Pending, etc.)
- `eck.status.available_nodes` - Available nodes
- `eck.status.available_instances` - Available instances
- `eck.status.total_nodes_in_cluster` - Total nodes in cluster
- `eck.status.total_instances` - Total instances

### Metrics Fields

#### Memory Metrics (`metrics.memory.*`)

- `metrics.memory.request_bytes` - Total memory requests (for all nodes/instances)
- `metrics.memory.limit_bytes` - Total memory limits
- `metrics.memory.request_per_node_bytes` - Memory request per individual node
- `metrics.memory.limit_per_node_bytes` - Memory limit per individual node

#### CPU Metrics (`metrics.cpu.*`)

- `metrics.cpu.request_cores` - Total CPU requests
- `metrics.cpu.limit_cores` - Total CPU limits
- `metrics.cpu.request_per_node_cores` - CPU request per individual node
- `metrics.cpu.limit_per_node_cores` - CPU limit per individual node

#### Node/Instance Metrics

- `metrics.nodes.count` - Number of nodes (Elasticsearch)
- `metrics.nodes.roles` - Node roles array
- `metrics.instance.number` - Instance number
- `metrics.instance.total_count` - Total instance count

## Sample Documents

### Elasticsearch Node Set Document

```json
{
  "@timestamp": "2025-07-30T14:02:10.461097+00:00",
  "ecs": { "version": "8.0.0" },
  "event": {
    "kind": "metric",
    "category": ["host"],
    "type": ["info"],
    "dataset": "eck.usage"
  },
  "orchestrator": {
    "type": "kubernetes",
    "namespace": "production",
    "resource": {
      "name": "production-es-hot",
      "type": "elasticsearch-nodeset",
      "id": "uuid-here"
    },
    "cluster": { "name": "k8s-prod" }
  },
  "service": {
    "name": "elasticsearch-hot",
    "type": "elasticsearch",
    "version": "8.11.0"
  },
  "eck": {
    "deployment": {
      "name": "production-es",
      "namespace": "production",
      "created": "2025-07-30T10:00:00Z"
    },
    "component": {
      "type": "elasticsearch-nodeset",
      "instance_name": "hot",
      "node_count": 3,
      "roles": ["data_hot", "ingest"],
      "parent_deployment": "production-es"
    },
    "status": {
      "health": "green",
      "phase": "Ready",
      "available_nodes": 3,
      "total_nodes_in_cluster": 8
    }
  },
  "host": {
    "name": "production-es-hot",
    "type": "elasticsearch-node",
    "containerized": true
  },
  "metrics": {
    "memory": {
      "request_bytes": 12884901888, // 12GB total (4GB x 3 nodes)
      "limit_bytes": 12884901888,
      "request_per_node_bytes": 4294967296, // 4GB per node
      "limit_per_node_bytes": 4294967296
    },
    "cpu": {
      "request_cores": 3.0, // 1 core x 3 nodes
      "limit_cores": 6.0, // 2 cores x 3 nodes
      "request_per_node_cores": 1.0,
      "limit_per_node_cores": 2.0
    },
    "nodes": {
      "count": 3,
      "roles": ["data_hot", "ingest"]
    }
  }
}
```

### Kibana Instance Document

```json
{
  "@timestamp": "2025-07-30T14:02:10.461097+00:00",
  "ecs": { "version": "8.0.0" },
  "event": { "kind": "metric", "category": ["host"] },
  "orchestrator": {
    "type": "kubernetes",
    "resource": {
      "name": "production-kibana-1",
      "type": "kibana-instance"
    }
  },
  "service": {
    "name": "kibana-kibana-1",
    "type": "kibana",
    "version": "8.11.0"
  },
  "eck": {
    "component": {
      "type": "kibana-instance",
      "instance_name": "kibana-1",
      "instance_number": 1,
      "parent_deployment": "production-kibana"
    }
  },
  "metrics": {
    "memory": {
      "request_bytes": 1073741824, // 1GB
      "limit_bytes": 2147483648 // 2GB
    },
    "cpu": {
      "request_cores": 0.5,
      "limit_cores": 1.0
    },
    "instance": {
      "number": 1,
      "total_count": 2
    }
  }
}
```

## Benefits

1. **ECS Compliance** - Documents follow Elastic Common Schema for better integration with Elastic Stack
2. **Granular Visibility** - Individual documents per component instance/node set
3. **Better Analytics** - Detailed resource metrics per component
4. **Improved Dashboards** - Rich metadata for creating comprehensive visualizations
5. **Scalable Structure** - Supports complex deployments with multiple node sets and instances
