#!/usr/bin/env python3
"""
ECK Usage Monitoring Script

This script monitors Elastic Cloud Kubernetes (ECK) managed components usage
and sends detailed metrics to Elasticsearch for analysis and monitoring.

Features:
- Extracts usage data from ECK licensing configmap
- Queries individual ECK managed resources (Elasticsearch, Kibana, APM, etc.)
- Collects granular metrics per component instance
- Sends data to Elasticsearch with API key authentication
"""

import json
import subprocess
import sys
import logging
import copy
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import argparse
import os
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Please install required packages: pip install requests")
    sys.exit(1)


def load_config_from_file(config_path: str = "config.env") -> Dict[str, str]:
    """
    Load configuration from a .env file

    Args:
        config_path: Path to the configuration file

    Returns:
        Dictionary containing configuration values
    """
    config = {}
    config_file = Path(config_path)

    if not config_file.exists():
        return config

    try:
        with open(config_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse key=value pairs
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    config[key] = value
                else:
                    print(
                        f"Warning: Invalid line {line_num} in {config_path}: {line}")

    except Exception as e:
        print(f"Error reading config file {config_path}: {e}")

    return config


def str_to_bool(value: str) -> bool:
    """Convert string to boolean"""
    if isinstance(value, bool):
        return value
    return value.lower() in ('true', '1', 'yes', 'on')


class ECKUsageMonitor:
    """Monitor ECK usage and send metrics to Elasticsearch"""

    def __init__(self, elasticsearch_url: str, api_key: str, index_prefix: str = "eck-usage"):
        """
        Initialize the ECK Usage Monitor

        Args:
            elasticsearch_url: Elasticsearch cluster URL
            api_key: API key for authentication
            index_prefix: Prefix for the Elasticsearch indices
        """
        self.elasticsearch_url = elasticsearch_url.rstrip('/')
        self.api_key = api_key
        self.index_prefix = index_prefix
        self.session = self._create_session()
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set authentication header
        session.headers.update({
            'Authorization': f'ApiKey {self.api_key}',
            'Content-Type': 'application/json'
        })

        return session

    def run_kubectl_command(self, command: List[str]) -> Optional[Dict]:
        """
        Execute kubectl command and return parsed JSON output

        Args:
            command: kubectl command as list of strings

        Returns:
            Parsed JSON output or None if command fails
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"kubectl command failed: {' '.join(command)}")
            self.logger.error(f"Error: {e.stderr}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON output: {e}")
            return None

    def get_licensing_data(self) -> Optional[Dict]:
        """Get ECK licensing data from configmap"""
        command = [
            'kubectl', '-n', 'elastic-system',
            'get', 'configmap', 'elastic-licensing',
            '-o', 'json'
        ]

        result = self.run_kubectl_command(command)
        if result and 'data' in result:
            return result['data']
        return None

    def get_eck_resources(self, resource_type: str, namespace: str = None) -> List[Dict]:
        """
        Get ECK managed resources of specific type

        Args:
            resource_type: Type of ECK resource (elasticsearch, kibana, apm, etc.)
            namespace: Kubernetes namespace (if None, searches all namespaces)

        Returns:
            List of resource objects
        """
        command = ['kubectl']

        command.extend(['get', resource_type, '-o', 'json'])

        if namespace:
            command.extend(['-n', namespace])
        else:
            command.append('-A')

        result = self.run_kubectl_command(command)
        if result and 'items' in result:
            return result['items']
        return []

    def extract_component_metrics(self, resource: Dict, component_type: str) -> List[Dict]:
        """
        Extract metrics from a specific ECK component, creating separate documents for each sub-component

        Args:
            resource: Kubernetes resource object
            component_type: Type of component (elasticsearch, kibana, etc.)

        Returns:
            List of dictionaries containing component metrics (one per sub-component)
        """
        metadata = resource.get('metadata', {})
        spec = resource.get('spec', {})
        status = resource.get('status', {})

        # Only process components that have a health status
        health = status.get('health', '').lower()
        if not health or health in ['unknown', '']:
            self.logger.debug(
                f"Skipping {component_type} {metadata.get('name', 'unknown')} - no health status")
            return []

        # Base ECS-compliant structure for all components
        base_document = self._create_base_ecs_document(
            metadata, spec, status, component_type)

        # Component-specific metrics - returns list of documents
        if component_type == 'elasticsearch':
            return self._extract_elasticsearch_metrics(base_document, spec, status)
        elif component_type == 'kibana':
            return self._extract_kibana_metrics(base_document, spec, status)
        elif component_type == 'apm':
            return self._extract_apm_metrics(base_document, spec, status)
        elif component_type == 'enterprisesearch':
            return self._extract_enterprise_search_metrics(base_document, spec, status)
        elif component_type == 'logstash':
            return self._extract_logstash_metrics(base_document, spec, status)
        elif component_type == 'agent':
            return self._extract_agent_metrics(base_document, spec, status)

        return [base_document]

    def _create_base_ecs_document(self, metadata: Dict, spec: Dict, status: Dict, component_type: str) -> Dict:
        """Create base ECS-compliant document structure"""
        current_time = datetime.now(timezone.utc)

        return {
            # ECS Base fields
            '@timestamp': current_time.isoformat(),
            'ecs': {
                'version': '8.0.0'
            },

            # ECS Event fields
            'event': {
                'kind': 'metric',
                'category': ['host'],
                'type': ['info'],
                'dataset': 'eck.usage',
                'module': 'eck-monitor',
                'created': current_time.isoformat()
            },

            # ECS Orchestrator fields (Kubernetes)
            'orchestrator': {
                'type': 'kubernetes',
                'organization': metadata.get('namespace', 'unknown'),
                'namespace': metadata.get('namespace', 'unknown'),
                'resource': {
                    'name': metadata.get('name', 'unknown'),
                    'type': component_type,
                    'id': metadata.get('uid', 'unknown')
                },
                'cluster': {
                    'name': self._get_cluster_name(),
                    'version': self._get_kubernetes_version()
                }
            },

            # ECS Service fields (ECK components as services)
            'service': {
                'name': f"eck-{component_type}",
                'type': component_type,
                'version': spec.get('version', 'unknown')
            },

            # Custom ECK fields
            'eck': {
                'deployment': {
                    'name': metadata.get('name', 'unknown'),
                    'namespace': metadata.get('namespace', 'unknown'),
                    'created': metadata.get('creationTimestamp'),
                    'uid': metadata.get('uid'),
                    'generation': metadata.get('generation', 0),
                    'labels': metadata.get('labels', {}),
                    'annotations': metadata.get('annotations', {})
                },
                'status': {
                    'health': status.get('health', 'unknown'),
                    'phase': status.get('phase', 'unknown')
                }
            },

            # ECS Host fields (will be populated per component instance)
            'host': {},

            # Custom metrics
            'metrics': {}
        }

    def _get_cluster_name(self) -> str:
        """Get Kubernetes cluster name"""
        try:
            result = subprocess.run(
                ['kubectl', 'config', 'current-context'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            return 'unknown'

    def _get_kubernetes_version(self) -> str:
        """Get Kubernetes cluster version"""
        try:
            result = subprocess.run(
                ['kubectl', 'version', '--client', '--short'],
                capture_output=True,
                text=True,
                check=True
            )
            # Extract version from output like "Client Version: v1.28.0"
            for line in result.stdout.split('\n'):
                if 'Client Version:' in line:
                    return line.split(': ')[-1].strip()
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            pass
        return 'unknown'

    def _extract_elasticsearch_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract Elasticsearch-specific metrics, creating one document per individual node"""
        documents = []
        node_sets = spec.get('nodeSets', [])

        # If no node sets, create a single document
        if not node_sets:
            doc = copy.deepcopy(base_document)
            doc['eck']['component'] = {
                'type': 'elasticsearch-node',
                'instance_name': 'default',
                'node_number': 1,
                'nodeset_name': 'default',
                'roles': [],
                'parent_deployment': base_document['eck']['deployment']['name']
            }
            doc['metrics'] = {
                'memory': {'request_bytes': 0, 'limit_bytes': 0},
                'cpu': {'request_cores': 0.0, 'limit_cores': 0.0}
            }
            documents.append(doc)
            return documents

        # Create a document for each individual node in each node set
        for nodeset_idx, node_set in enumerate(node_sets):
            node_set_name = node_set.get('name', f'nodeset-{nodeset_idx}')
            node_count = node_set.get('count', 0)
            node_roles = node_set.get('config', {}).get('node.roles', [])

            # Extract resource requirements for nodes in this set
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            pod_template = node_set.get('podTemplate', {})
            containers = pod_template.get('spec', {}).get('containers', [])

            for container in containers:
                if container.get('name') == 'elasticsearch':
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    limits = resources.get('limits', {})

                    memory_req_bytes = self._parse_memory_to_bytes(
                        requests.get('memory', '0'))
                    memory_limit_bytes = self._parse_memory_to_bytes(
                        limits.get('memory', '0'))
                    cpu_req_cores = self._parse_cpu_to_cores(
                        requests.get('cpu', '0'))
                    cpu_limit_cores = self._parse_cpu_to_cores(
                        limits.get('cpu', '0'))
                    break

            # Create individual documents for each node in this node set
            for node_idx in range(node_count):
                doc = copy.deepcopy(base_document)
                node_number = node_idx + 1

                # Update orchestrator resource info for this specific node
                doc['orchestrator']['resource'][
                    'name'] = f"{base_document['orchestrator']['resource']['name']}-{node_set_name}-{node_number}"
                doc['orchestrator']['resource']['type'] = 'elasticsearch-node'

                # Update service info - use StatefulSet name for Elasticsearch
                deployment_name = base_document['eck']['deployment']['name']
                doc['service']['name'] = f"{deployment_name}-es-{node_set_name}"

                # ECK component-specific fields
                doc['eck']['component'] = {
                    'type': 'elasticsearch-node',
                    'instance_name': f"{node_set_name}-{node_number}",
                    'node_number': node_number,
                    'nodeset_name': node_set_name,
                    'nodeset_total_nodes': node_count,
                    'roles': node_roles,
                    'parent_deployment': base_document['eck']['deployment']['name'],
                    'pod_name': f"{deployment_name}-es-{node_set_name}-{node_idx}"
                }

                # Update status with node-specific info
                doc['eck']['status'].update({
                    'available_nodes': status.get('availableNodes', 0),
                    'total_nodes_in_cluster': sum(ns.get('count', 0) for ns in node_sets),
                    'nodeset_available_nodes': min(node_count, status.get('availableNodes', 0))
                })

                # Host information (per individual node)
                doc['host'] = {
                    'name': f"{base_document['eck']['deployment']['name']}-{node_set_name}-{node_number}",
                    'type': 'elasticsearch-node',
                    'architecture': 'x86_64',
                    'containerized': True
                }

                # Metrics for this individual node
                doc['metrics'] = {
                    'memory': {
                        'request_bytes': memory_req_bytes,
                        'limit_bytes': memory_limit_bytes
                    },
                    'cpu': {
                        'request_cores': cpu_req_cores,
                        'limit_cores': cpu_limit_cores
                    },
                    'node': {
                        'number': node_number,
                        'roles': node_roles,
                        'nodeset_name': node_set_name,
                        'nodeset_total_count': node_count
                    }
                }

                documents.append(doc)

        return documents

    def _extract_kibana_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract Kibana-specific metrics, creating one document per instance"""
        documents = []
        instance_count = spec.get('count', 1)

        # Create a document for each Kibana instance
        for i in range(instance_count):
            doc = copy.deepcopy(base_document)
            instance_number = i + 1
            instance_name = f"kibana-{instance_number}" if instance_count > 1 else "kibana"

            # Update orchestrator resource info for this specific instance
            doc['orchestrator']['resource'][
                'name'] = f"{base_document['orchestrator']['resource']['name']}-{instance_name}"
            doc['orchestrator']['resource']['type'] = 'kibana-instance'

            # Update service info - use Deployment name for Kibana
            deployment_name = base_document['eck']['deployment']['name']
            doc['service']['name'] = f"{deployment_name}-kb"

            # ECK component-specific fields
            doc['eck']['component'] = {
                'type': 'kibana-instance',
                'instance_name': instance_name,
                'instance_number': instance_number,
                'total_instances': instance_count,
                'parent_deployment': base_document['eck']['deployment']['name'],
                'elasticsearch_ref': spec.get('elasticsearchRef', {}),
                'pod_name': f"{deployment_name}-kb-{instance_number-1:x}" if instance_count > 1 else f"{deployment_name}-kb-0"
            }

            # Update status
            doc['eck']['status'].update({
                'available_instances': status.get('availableInstances', 0),
                'total_instances': instance_count
            })

            # Extract resource requirements for this individual instance
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            pod_template = spec.get('podTemplate', {})
            containers = pod_template.get('spec', {}).get('containers', [])

            for container in containers:
                if container.get('name') == 'kibana':
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    limits = resources.get('limits', {})

                    memory_req_bytes = self._parse_memory_to_bytes(
                        requests.get('memory', '0'))
                    memory_limit_bytes = self._parse_memory_to_bytes(
                        limits.get('memory', '0'))
                    cpu_req_cores = self._parse_cpu_to_cores(
                        requests.get('cpu', '0'))
                    cpu_limit_cores = self._parse_cpu_to_cores(
                        limits.get('cpu', '0'))
                    break

            # Host information for this individual instance
            doc['host'] = {
                'name': f"{base_document['eck']['deployment']['name']}-{instance_name}",
                'type': 'kibana-instance',
                'architecture': 'x86_64',
                'containerized': True
            }

            # Metrics for this individual instance
            doc['metrics'] = {
                'memory': {
                    'request_bytes': memory_req_bytes,
                    'limit_bytes': memory_limit_bytes
                },
                'cpu': {
                    'request_cores': cpu_req_cores,
                    'limit_cores': cpu_limit_cores
                },
                'instance': {
                    'number': instance_number,
                    'total_count': instance_count
                }
            }

            documents.append(doc)

        return documents

    def _extract_apm_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract APM Server-specific metrics, creating one document per instance"""
        documents = []
        instance_count = spec.get('count', 1)

        # Create a document for each APM Server instance
        for i in range(instance_count):
            doc = copy.deepcopy(base_document)
            instance_name = f"apm-{i+1}" if instance_count > 1 else "apm"

            # Update orchestrator resource info for this specific instance
            doc['orchestrator']['resource'][
                'name'] = f"{base_document['orchestrator']['resource']['name']}-{instance_name}"
            doc['orchestrator']['resource']['type'] = 'apm-instance'

            # Update service info - use Deployment name for APM Server
            deployment_name = base_document['eck']['deployment']['name']
            doc['service']['name'] = f"{deployment_name}-apm-server"

            # ECK component-specific fields
            doc['eck']['component'] = {
                'type': 'apm-instance',
                'instance_name': instance_name,
                'instance_number': i + 1,
                'total_instances': instance_count,
                'parent_deployment': base_document['eck']['deployment']['name'],
                'elasticsearch_ref': spec.get('elasticsearchRef', {}),
                'kibana_ref': spec.get('kibanaRef', {}),
                'pod_name': f"{deployment_name}-apm-server-{i:x}" if instance_count > 1 else f"{deployment_name}-apm-server-0"
            }

            # Update status
            doc['eck']['status'].update({
                'available_instances': status.get('availableInstances', 0),
                'total_instances': instance_count
            })

            # Extract resource requirements
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            pod_template = spec.get('podTemplate', {})
            containers = pod_template.get('spec', {}).get('containers', [])

            for container in containers:
                if container.get('name') == 'apm-server':
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    limits = resources.get('limits', {})

                    memory_req_bytes = self._parse_memory_to_bytes(
                        requests.get('memory', '0'))
                    memory_limit_bytes = self._parse_memory_to_bytes(
                        limits.get('memory', '0'))
                    cpu_req_cores = self._parse_cpu_to_cores(
                        requests.get('cpu', '0'))
                    cpu_limit_cores = self._parse_cpu_to_cores(
                        limits.get('cpu', '0'))
                    break

            # Host information
            doc['host'] = {
                'name': f"{base_document['eck']['deployment']['name']}-{instance_name}",
                'type': 'apm-instance',
                'architecture': 'x86_64',
                'containerized': True
            }

            # Metrics for this instance
            doc['metrics'] = {
                'memory': {
                    'request_bytes': memory_req_bytes,
                    'limit_bytes': memory_limit_bytes
                },
                'cpu': {
                    'request_cores': cpu_req_cores,
                    'limit_cores': cpu_limit_cores
                },
                'instance': {
                    'number': i + 1,
                    'total_count': instance_count
                }
            }

            documents.append(doc)

        return documents

    def _extract_enterprise_search_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract Enterprise Search-specific metrics, creating one document per instance"""
        documents = []
        instance_count = spec.get('count', 1)

        # Create a document for each Enterprise Search instance
        for i in range(instance_count):
            doc = copy.deepcopy(base_document)
            instance_name = f"entsearch-{i+1}" if instance_count > 1 else "entsearch"

            # Update orchestrator resource info for this specific instance
            doc['orchestrator']['resource'][
                'name'] = f"{base_document['orchestrator']['resource']['name']}-{instance_name}"
            doc['orchestrator']['resource']['type'] = 'enterprisesearch-instance'

            # Update service info - use Deployment name for Enterprise Search
            deployment_name = base_document['eck']['deployment']['name']
            doc['service']['name'] = f"{deployment_name}-ent"

            # ECK component-specific fields
            doc['eck']['component'] = {
                'type': 'enterprisesearch-instance',
                'instance_name': instance_name,
                'instance_number': i + 1,
                'total_instances': instance_count,
                'parent_deployment': base_document['eck']['deployment']['name'],
                'elasticsearch_ref': spec.get('elasticsearchRef', {}),
                'pod_name': f"{deployment_name}-ent-{i:x}" if instance_count > 1 else f"{deployment_name}-ent-0"
            }

            # Update status
            doc['eck']['status'].update({
                'available_instances': status.get('availableInstances', 0),
                'total_instances': instance_count
            })

            # Extract resource requirements
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            pod_template = spec.get('podTemplate', {})
            containers = pod_template.get('spec', {}).get('containers', [])

            for container in containers:
                if container.get('name') == 'enterprise-search':
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    limits = resources.get('limits', {})

                    memory_req_bytes = self._parse_memory_to_bytes(
                        requests.get('memory', '0'))
                    memory_limit_bytes = self._parse_memory_to_bytes(
                        limits.get('memory', '0'))
                    cpu_req_cores = self._parse_cpu_to_cores(
                        requests.get('cpu', '0'))
                    cpu_limit_cores = self._parse_cpu_to_cores(
                        limits.get('cpu', '0'))
                    break

            # Host information
            doc['host'] = {
                'name': f"{base_document['eck']['deployment']['name']}-{instance_name}",
                'type': 'enterprisesearch-instance',
                'architecture': 'x86_64',
                'containerized': True
            }

            # Metrics for this instance
            doc['metrics'] = {
                'memory': {
                    'request_bytes': memory_req_bytes,
                    'limit_bytes': memory_limit_bytes
                },
                'cpu': {
                    'request_cores': cpu_req_cores,
                    'limit_cores': cpu_limit_cores
                },
                'instance': {
                    'number': i + 1,
                    'total_count': instance_count
                }
            }

            documents.append(doc)

        return documents

    def _extract_logstash_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract Logstash-specific metrics, creating one document per instance"""
        documents = []
        instance_count = spec.get('count', 1)

        # Create a document for each Logstash instance
        for i in range(instance_count):
            doc = copy.deepcopy(base_document)
            instance_name = f"logstash-{i+1}" if instance_count > 1 else "logstash"

            # Update orchestrator resource info for this specific instance
            doc['orchestrator']['resource'][
                'name'] = f"{base_document['orchestrator']['resource']['name']}-{instance_name}"
            doc['orchestrator']['resource']['type'] = 'logstash-instance'

            # Update service info - use StatefulSet name for Logstash
            deployment_name = base_document['eck']['deployment']['name']
            doc['service']['name'] = f"{deployment_name}-ls"

            # ECK component-specific fields
            doc['eck']['component'] = {
                'type': 'logstash-instance',
                'instance_name': instance_name,
                'instance_number': i + 1,
                'total_instances': instance_count,
                'parent_deployment': base_document['eck']['deployment']['name'],
                'elasticsearch_refs': spec.get('elasticsearchRefs', []),
                'pod_name': f"{deployment_name}-ls-{i}"
            }

            # Update status
            doc['eck']['status'].update({
                'available_instances': status.get('availableInstances', 0),
                'total_instances': instance_count
            })

            # Extract resource requirements
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            pod_template = spec.get('podTemplate', {})
            containers = pod_template.get('spec', {}).get('containers', [])

            for container in containers:
                if container.get('name') == 'logstash':
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    limits = resources.get('limits', {})

                    memory_req_bytes = self._parse_memory_to_bytes(
                        requests.get('memory', '0'))
                    memory_limit_bytes = self._parse_memory_to_bytes(
                        limits.get('memory', '0'))
                    cpu_req_cores = self._parse_cpu_to_cores(
                        requests.get('cpu', '0'))
                    cpu_limit_cores = self._parse_cpu_to_cores(
                        limits.get('cpu', '0'))
                    break

            # Host information
            doc['host'] = {
                'name': f"{base_document['eck']['deployment']['name']}-{instance_name}",
                'type': 'logstash-instance',
                'architecture': 'x86_64',
                'containerized': True
            }

            # Metrics for this instance
            doc['metrics'] = {
                'memory': {
                    'request_bytes': memory_req_bytes,
                    'limit_bytes': memory_limit_bytes
                },
                'cpu': {
                    'request_cores': cpu_req_cores,
                    'limit_cores': cpu_limit_cores
                },
                'instance': {
                    'number': i + 1,
                    'total_count': instance_count
                }
            }

            documents.append(doc)

        return documents

    def _extract_agent_metrics(self, base_document: Dict, spec: Dict, status: Dict) -> List[Dict]:
        """Extract Elastic Agent-specific metrics, creating one document per instance"""
        documents = []
        instance_count = spec.get('count', 1)

        # Create a document for each Elastic Agent instance
        for i in range(instance_count):
            doc = copy.deepcopy(base_document)
            instance_name = f"agent-{i+1}" if instance_count > 1 else "agent"

            # Update orchestrator resource info for this specific instance
            doc['orchestrator']['resource'][
                'name'] = f"{base_document['orchestrator']['resource']['name']}-{instance_name}"
            doc['orchestrator']['resource']['type'] = 'agent-instance'

            # Update service info - use Deployment/DaemonSet name for Elastic Agent
            deployment_name = base_document['eck']['deployment']['name']
            doc['service']['name'] = f"{deployment_name}-agent"

            # ECK component-specific fields
            doc['eck']['component'] = {
                'type': 'agent-instance',
                'instance_name': instance_name,
                'instance_number': i + 1,
                'total_instances': instance_count,
                'parent_deployment': base_document['eck']['deployment']['name'],
                'elasticsearch_refs': spec.get('elasticsearchRefs', []),
                'kibana_ref': spec.get('kibanaRef', {}),
                'fleet_server_enabled': spec.get('fleetServerEnabled', False),
                'mode': spec.get('mode', 'fleet'),
                'deployment_mode': (spec.get('deployment', {}).get('replicas', instance_count)
                                    if spec.get('deployment') else instance_count),
                'pod_name': (f"{deployment_name}-agent-{i:x}" if spec.get('deployment')
                             else f"{deployment_name}-agent-node-{i}")
            }

            # Update status
            doc['eck']['status'].update({
                'available_instances': status.get('availableInstances', 0),
                'total_instances': instance_count,
                'expected_instances': status.get('expectedInstances', instance_count)
            })

            # Extract resource requirements
            memory_req_bytes = 0
            memory_limit_bytes = 0
            cpu_req_cores = 0.0
            cpu_limit_cores = 0.0

            # Check for Deployment mode resources
            deployment = spec.get('deployment', {})
            if deployment:
                pod_template = deployment.get('podTemplate', {})
                containers = pod_template.get('spec', {}).get('containers', [])

                for container in containers:
                    if container.get('name') == 'agent':
                        resources = container.get('resources', {})
                        requests = resources.get('requests', {})
                        limits = resources.get('limits', {})

                        memory_req_bytes = self._parse_memory_to_bytes(
                            requests.get('memory', '0'))
                        memory_limit_bytes = self._parse_memory_to_bytes(
                            limits.get('memory', '0'))
                        cpu_req_cores = self._parse_cpu_to_cores(
                            requests.get('cpu', '0'))
                        cpu_limit_cores = self._parse_cpu_to_cores(
                            limits.get('cpu', '0'))
                        break

            # Check for DaemonSet mode resources (fallback)
            if memory_req_bytes == 0 and cpu_req_cores == 0.0:
                daemon_set = spec.get('daemonSet', {})
                if daemon_set:
                    pod_template = daemon_set.get('podTemplate', {})
                    containers = pod_template.get(
                        'spec', {}).get('containers', [])

                    for container in containers:
                        if container.get('name') == 'agent':
                            resources = container.get('resources', {})
                            requests = resources.get('requests', {})
                            limits = resources.get('limits', {})

                            memory_req_bytes = self._parse_memory_to_bytes(
                                requests.get('memory', '0'))
                            memory_limit_bytes = self._parse_memory_to_bytes(
                                limits.get('memory', '0'))
                            cpu_req_cores = self._parse_cpu_to_cores(
                                requests.get('cpu', '0'))
                            cpu_limit_cores = self._parse_cpu_to_cores(
                                limits.get('cpu', '0'))
                            break

            # Host information
            doc['host'] = {
                'name': f"{base_document['eck']['deployment']['name']}-{instance_name}",
                'type': 'agent-instance',
                'architecture': 'x86_64',
                'containerized': True
            }

            # Metrics for this instance
            doc['metrics'] = {
                'memory': {
                    'request_bytes': memory_req_bytes,
                    'limit_bytes': memory_limit_bytes
                },
                'cpu': {
                    'request_cores': cpu_req_cores,
                    'limit_cores': cpu_limit_cores
                },
                'instance': {
                    'number': i + 1,
                    'total_count': instance_count
                },
                'agent': {
                    'mode': spec.get('mode', 'fleet'),
                    'fleet_server_enabled': spec.get('fleetServerEnabled', False),
                    'policy_id': spec.get('policyID', ''),
                    'deployment_mode': 'deployment' if spec.get('deployment') else 'daemonset'
                }
            }

            documents.append(doc)

        return documents

    def _parse_memory_to_bytes(self, memory_str) -> int:
        """Convert Kubernetes memory string to bytes"""
        if not memory_str or memory_str == '0' or memory_str == 0:
            return 0

        # Convert to string if it's an integer
        if isinstance(memory_str, int):
            return memory_str

        memory_str = str(memory_str).strip()

        # Handle different units
        multipliers = {
            'Ki': 1024,
            'Mi': 1024 ** 2,
            'Gi': 1024 ** 3,
            'Ti': 1024 ** 4,
            'K': 1000,
            'M': 1000 ** 2,
            'G': 1000 ** 3,
            'T': 1000 ** 4,
        }

        for unit, multiplier in multipliers.items():
            if memory_str.endswith(unit):
                try:
                    value = float(memory_str[:-len(unit)])
                    return int(value * multiplier)
                except ValueError:
                    return 0

        # Try to parse as plain number (bytes)
        try:
            return int(memory_str)
        except ValueError:
            return 0

    def _parse_cpu_to_cores(self, cpu_str) -> float:
        """Convert Kubernetes CPU string to cores"""
        if not cpu_str or cpu_str == '0' or cpu_str == 0:
            return 0.0

        # Convert to string if it's a number
        if isinstance(cpu_str, (int, float)):
            return float(cpu_str)

        cpu_str = str(cpu_str).strip()

        # Handle millicores
        if cpu_str.endswith('m'):
            try:
                value = float(cpu_str[:-1])
                return value / 1000.0
            except ValueError:
                return 0.0

        # Try to parse as plain number (cores)
        try:
            return float(cpu_str)
        except ValueError:
            return 0.0

    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all ECK metrics"""
        self.logger.info("Starting ECK metrics collection")

        # Get licensing data
        licensing_data = self.get_licensing_data()
        if not licensing_data:
            self.logger.error("Failed to retrieve licensing data")
            return {}

        # Get all ECK resources
        resource_types = [
            ('elasticsearch', 'elasticsearches'),
            ('kibana', 'kibanas'),
            ('apm', 'apmservers'),
            ('enterprisesearch', 'enterprisesearches'),
            ('logstash', 'logstashes'),
            ('agent', 'agents'),
        ]

        all_metrics = {
            'licensing': licensing_data,
            'components': [],
            'summary': {
                'total_components': 0,
                'components_by_type': {},
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
            }
        }

        for component_type, k8s_resource_type in resource_types:
            self.logger.info(f"Collecting {component_type} metrics")
            resources = self.get_eck_resources(k8s_resource_type)

            component_count = 0
            sub_component_count = 0
            for resource in resources:
                # extract_component_metrics now returns a list of documents
                component_documents = self.extract_component_metrics(
                    resource, component_type)

                # Add all sub-component documents
                all_metrics['components'].extend(component_documents)
                component_count += 1
                sub_component_count += len(component_documents)

            all_metrics['summary']['components_by_type'][component_type] = {
                'deployments': component_count,
                'instances': sub_component_count
            }
            all_metrics['summary']['total_components'] += sub_component_count

        self.logger.info(
            f"Collected metrics for {all_metrics['summary']['total_components']} component instances "
            f"from {sum(ct['deployments'] for ct in all_metrics['summary']['components_by_type'].values())} "
            f"deployments")
        return all_metrics

    def send_to_elasticsearch(self, metrics: Dict[str, Any]) -> bool:
        """Send metrics to Elasticsearch"""
        if not metrics:
            self.logger.error("No metrics to send")
            return False

        success = True
        timestamp = datetime.now()
        date_suffix = timestamp.strftime("%Y.%m.%d")

        # Send licensing data (make it ECS-compliant)
        licensing_index = f"{self.index_prefix}-licensing-{date_suffix}"
        licensing_doc = {
            '@timestamp': timestamp.isoformat(),
            'ecs': {'version': '8.0.0'},
            'event': {
                'kind': 'metric',
                'category': ['configuration'],
                'type': ['info'],
                'dataset': 'eck.licensing',
                'module': 'eck-monitor',
                'created': timestamp.isoformat()
            },
            'orchestrator': {
                'type': 'kubernetes',
                'cluster': {
                    'name': self._get_cluster_name()
                }
            },
            'service': {
                'name': 'eck-operator',
                'type': 'orchestrator'
            },
            'eck': {
                'licensing': metrics['licensing']
            },
            'collection_timestamp': timestamp.isoformat(),
        }

        if not self._send_document(licensing_index, licensing_doc):
            success = False

        # Send component metrics
        components_index = f"{self.index_prefix}-components-{date_suffix}"
        for component in metrics['components']:
            if not self._send_document(components_index, component):
                success = False

        # Send summary (make it ECS-compliant)
        summary_index = f"{self.index_prefix}-summary-{date_suffix}"
        summary_doc = {
            '@timestamp': timestamp.isoformat(),
            'ecs': {'version': '8.0.0'},
            'event': {
                'kind': 'metric',
                'category': ['configuration'],
                'type': ['info'],
                'dataset': 'eck.summary',
                'module': 'eck-monitor',
                'created': timestamp.isoformat()
            },
            'orchestrator': {
                'type': 'kubernetes',
                'cluster': {
                    'name': self._get_cluster_name()
                }
            },
            'service': {
                'name': 'eck-monitor',
                'type': 'monitoring'
            },
            'eck': {
                'summary': {
                    'total_components': metrics['summary']['total_components'],
                    'collection_timestamp': metrics['summary']['collection_timestamp'],
                    'components_by_type': metrics['summary']['components_by_type']
                }
            }
        }

        if not self._send_document(summary_index, summary_doc):
            success = False

        return success

    def _send_document(self, index: str, document: Dict) -> bool:
        """Send a single document to Elasticsearch"""
        url = f"{self.elasticsearch_url}/{index}/_doc"

        try:
            response = self.session.post(url, json=document, timeout=30)
            response.raise_for_status()

            result = response.json()
            if result.get('result') in ['created', 'updated']:
                self.logger.debug(f"Successfully sent document to {index}")
                return True
            else:
                self.logger.error(f"Unexpected response for {index}: {result}")
                return False

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send document to {index}: {e}")
            return False
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse response for {index}: {e}")
            return False

    def create_index_templates(self) -> bool:
        """Create index templates for better data organization"""
        templates = [
            {
                'name': f"{self.index_prefix}-licensing",
                'pattern': f"{self.index_prefix}-licensing-*",
                'mappings': {
                    'properties': {
                        '@timestamp': {'type': 'date'},
                        'ecs': {
                            'properties': {
                                'version': {'type': 'keyword'}
                            }
                        },
                        'event': {
                            'properties': {
                                'kind': {'type': 'keyword'},
                                'category': {'type': 'keyword'},
                                'type': {'type': 'keyword'},
                                'dataset': {'type': 'keyword'},
                                'module': {'type': 'keyword'},
                                'created': {'type': 'date'}
                            }
                        },
                        'orchestrator': {
                            'properties': {
                                'type': {'type': 'keyword'},
                                'cluster': {
                                    'properties': {
                                        'name': {'type': 'keyword'}
                                    }
                                }
                            }
                        },
                        'service': {
                            'properties': {
                                'name': {'type': 'keyword'},
                                'type': {'type': 'keyword'}
                            }
                        },
                        'collection_timestamp': {'type': 'date'},
                        'eck': {
                            'properties': {
                                'licensing': {
                                    'properties': {
                                        'eck_license_expiry_date': {'type': 'date'},
                                        'total_managed_memory_bytes': {'type': 'long'},
                                        'elasticsearch_memory_bytes': {'type': 'long'},
                                        'kibana_memory_bytes': {'type': 'long'},
                                        'apm_memory_bytes': {'type': 'long'},
                                        'enterprise_search_memory_bytes': {'type': 'long'},
                                        'logstash_memory_bytes': {'type': 'long'},
                                        'enterprise_resource_units': {'type': 'integer'},
                                        'max_enterprise_resource_units': {'type': 'integer'},
                                        'eck_license_level': {'type': 'keyword'},
                                        'timestamp': {'type': 'date'}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            {
                'name': f"{self.index_prefix}-components",
                'pattern': f"{self.index_prefix}-components-*",
                'mappings': {
                    'properties': {
                        '@timestamp': {'type': 'date'},
                        'ecs': {
                            'properties': {
                                'version': {'type': 'keyword'}
                            }
                        },
                        'event': {
                            'properties': {
                                'kind': {'type': 'keyword'},
                                'category': {'type': 'keyword'},
                                'type': {'type': 'keyword'},
                                'dataset': {'type': 'keyword'},
                                'module': {'type': 'keyword'},
                                'created': {'type': 'date'}
                            }
                        },
                        'orchestrator': {
                            'properties': {
                                'type': {'type': 'keyword'},
                                'organization': {'type': 'keyword'},
                                'namespace': {'type': 'keyword'},
                                'resource': {
                                    'properties': {
                                        'name': {'type': 'keyword'},
                                        'type': {'type': 'keyword'},
                                        'id': {'type': 'keyword'}
                                    }
                                },
                                'cluster': {
                                    'properties': {
                                        'name': {'type': 'keyword'},
                                        'version': {'type': 'keyword'}
                                    }
                                }
                            }
                        },
                        'service': {
                            'properties': {
                                'name': {'type': 'keyword'},
                                'type': {'type': 'keyword'},
                                'version': {'type': 'keyword'}
                            }
                        },
                        'host': {
                            'properties': {
                                'name': {'type': 'keyword'},
                                'type': {'type': 'keyword'},
                                'architecture': {'type': 'keyword'},
                                'containerized': {'type': 'boolean'}
                            }
                        },
                        'eck': {
                            'properties': {
                                'deployment': {
                                    'properties': {
                                        'name': {'type': 'keyword'},
                                        'namespace': {'type': 'keyword'},
                                        'created': {'type': 'date'},
                                        'uid': {'type': 'keyword'},
                                        'generation': {'type': 'long'}
                                    }
                                },
                                'component': {
                                    'properties': {
                                        'type': {'type': 'keyword'},
                                        'instance_name': {'type': 'keyword'},
                                        'instance_number': {'type': 'integer'},
                                        'node_count': {'type': 'integer'},
                                        'roles': {'type': 'keyword'},
                                        'parent_deployment': {'type': 'keyword'}
                                    }
                                },
                                'status': {
                                    'properties': {
                                        'health': {'type': 'keyword'},
                                        'phase': {'type': 'keyword'},
                                        'available_nodes': {'type': 'integer'},
                                        'available_instances': {'type': 'integer'},
                                        'total_nodes_in_cluster': {'type': 'integer'},
                                        'total_instances': {'type': 'integer'}
                                    }
                                }
                            }
                        },
                        'metrics': {
                            'properties': {
                                'memory': {
                                    'properties': {
                                        'request_bytes': {'type': 'long'},
                                        'limit_bytes': {'type': 'long'},
                                        'request_per_node_bytes': {'type': 'long'},
                                        'limit_per_node_bytes': {'type': 'long'}
                                    }
                                },
                                'cpu': {
                                    'properties': {
                                        'request_cores': {'type': 'float'},
                                        'limit_cores': {'type': 'float'},
                                        'request_per_node_cores': {'type': 'float'},
                                        'limit_per_node_cores': {'type': 'float'}
                                    }
                                },
                                'nodes': {
                                    'properties': {
                                        'count': {'type': 'integer'},
                                        'roles': {'type': 'keyword'}
                                    }
                                },
                                'instance': {
                                    'properties': {
                                        'number': {'type': 'integer'},
                                        'total_count': {'type': 'integer'}
                                    }
                                },
                                'agent': {
                                    'properties': {
                                        'mode': {'type': 'keyword'},
                                        'fleet_server_enabled': {'type': 'boolean'},
                                        'policy_id': {'type': 'keyword'},
                                        'deployment_mode': {'type': 'keyword'}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            {
                'name': f"{self.index_prefix}-summary",
                'pattern': f"{self.index_prefix}-summary-*",
                'mappings': {
                    'properties': {
                        '@timestamp': {'type': 'date'},
                        'ecs': {
                            'properties': {
                                'version': {'type': 'keyword'}
                            }
                        },
                        'event': {
                            'properties': {
                                'kind': {'type': 'keyword'},
                                'category': {'type': 'keyword'},
                                'type': {'type': 'keyword'},
                                'dataset': {'type': 'keyword'},
                                'module': {'type': 'keyword'},
                                'created': {'type': 'date'}
                            }
                        },
                        'orchestrator': {
                            'properties': {
                                'type': {'type': 'keyword'},
                                'cluster': {
                                    'properties': {
                                        'name': {'type': 'keyword'}
                                    }
                                }
                            }
                        },
                        'service': {
                            'properties': {
                                'name': {'type': 'keyword'},
                                'type': {'type': 'keyword'}
                            }
                        },
                        'eck': {
                            'properties': {
                                'summary': {
                                    'properties': {
                                        'total_components': {'type': 'integer'},
                                        'collection_timestamp': {'type': 'date'},
                                        'components_by_type': {
                                            'properties': {
                                                'elasticsearch': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                },
                                                'kibana': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                },
                                                'apm': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                },
                                                'enterprisesearch': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                },
                                                'logstash': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                },
                                                'agent': {
                                                    'properties': {
                                                        'deployments': {'type': 'integer'},
                                                        'instances': {'type': 'integer'}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        ]

        success = True
        for template in templates:
            url = f"{self.elasticsearch_url}/_index_template/{template['name']}"

            template_body = {
                'index_patterns': [template['pattern']],
                'template': {
                    'mappings': template['mappings'],
                    'settings': {
                        'number_of_shards': 1,
                        'number_of_replicas': 1
                    }
                }
            }

            try:
                response = self.session.put(
                    url, json=template_body, timeout=30)
                response.raise_for_status()
                self.logger.info(f"Created index template: {template['name']}")
            except requests.exceptions.RequestException as e:
                self.logger.error(
                    f"Failed to create index template {template['name']}: {e}")
                success = False

        return success


def setup_argument_parser(file_config: Dict[str, str], config_file_path: str) -> argparse.ArgumentParser:
    """Set up command line argument parser with config file defaults"""
    parser = argparse.ArgumentParser(
        description='ECK Usage Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration can be provided via:
1. Command line arguments (highest priority)
2. config.env file (if present)
3. Environment variables (lowest priority)

Example config.env file:
    ELASTICSEARCH_URL=https://your-cluster.com:9200
    ELASTICSEARCH_API_KEY=your_api_key_here
    INDEX_PREFIX=eck-usage
    CREATE_TEMPLATES=true
    VERBOSE=false
        """
    )

    # Get default values from config file or environment variables
    def get_default(key: str, default=None):
        """Get default value from file config, then env vars, then provided default"""
        return file_config.get(key, os.getenv(key, default))

    # Command line arguments with defaults from config
    elasticsearch_url_default = get_default('ELASTICSEARCH_URL')
    api_key_default = get_default('ELASTICSEARCH_API_KEY')

    parser.add_argument('--elasticsearch-url',
                        default=elasticsearch_url_default,
                        help='Elasticsearch cluster URL (can be set in config.env as ELASTICSEARCH_URL)')
    parser.add_argument('--api-key',
                        default=api_key_default,
                        help='Elasticsearch API key for authentication (can be set in config.env as ELASTICSEARCH_API_KEY)')
    parser.add_argument('--index-prefix',
                        default=get_default('INDEX_PREFIX', 'eck-usage'),
                        help='Prefix for Elasticsearch indices (default: eck-usage)')
    parser.add_argument('--create-templates',
                        action='store_true',
                        default=str_to_bool(get_default(
                            'CREATE_TEMPLATES', 'false')),
                        help='Create index templates before sending data')
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        default=str_to_bool(get_default('VERBOSE', 'false')),
                        help='Enable verbose logging')
    parser.add_argument('--dry-run',
                        action='store_true',
                        default=str_to_bool(get_default('DRY_RUN', 'false')),
                        help='Collect metrics but do not send to Elasticsearch')
    parser.add_argument('--config-file',
                        default=config_file_path,
                        help='Path to configuration file (default: config.env)')

    return parser


def validate_configuration(args, parser) -> bool:
    """Validate required configuration arguments"""
    if not args.elasticsearch_url:
        print("Error: Elasticsearch URL is required. Set it via --elasticsearch-url argument "
              "or ELASTICSEARCH_URL in config.env")
        parser.print_help()
        return False

    if not args.api_key:
        print("Error: Elasticsearch API key is required. Set it via --api-key argument "
              "or ELASTICSEARCH_API_KEY in config.env")
        parser.print_help()
        return False

    return True


def setup_logging_and_show_config(args, file_config: Dict[str, str]):
    """Set up logging and show configuration information"""
    # Set up logging early
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Show configuration source info
    logger = logging.getLogger(__name__)
    if file_config:
        logger.info(f"Loaded configuration from: {args.config_file}")
        if args.verbose:
            logger.info(f"Config values loaded: {list(file_config.keys())}")

    if args.verbose:
        logger.info(f"Elasticsearch URL: {args.elasticsearch_url}")
        logger.info(f"Index prefix: {args.index_prefix}")
        logger.info(f"Create templates: {args.create_templates}")
        logger.info(f"Dry run mode: {args.dry_run}")


def handle_templates_creation(monitor, args) -> bool:
    """Handle index template creation based on arguments"""
    if args.create_templates and not args.dry_run:
        monitor.logger.info("Creating index templates")
        if not monitor.create_index_templates():
            monitor.logger.error("Failed to create some index templates")
            return False
    elif args.create_templates and args.dry_run:
        monitor.logger.info("Dry run: Would create index templates")
    return True


def handle_dry_run_output(monitor, metrics, args) -> int:
    """Handle output for dry run mode"""
    monitor.logger.info("Dry run mode: Metrics collected successfully")
    monitor.logger.info(
        f"Would send {metrics['summary']['total_components']} component instances to Elasticsearch")
    monitor.logger.info(
        f"Components by type: {metrics['summary']['components_by_type']}")
    monitor.logger.info("Use --verbose to see detailed metrics")
    if args.verbose:
        sample_component = metrics['components'][0] if metrics['components'] else {
        }
        monitor.logger.debug(
            f"Sample component metric: {json.dumps(sample_component, indent=2)}")
    return 0


def run_monitor(args) -> int:
    """Run the ECK monitor with the given arguments"""
    # Initialize monitor
    monitor = ECKUsageMonitor(
        elasticsearch_url=args.elasticsearch_url,
        api_key=args.api_key,
        index_prefix=args.index_prefix
    )

    try:
        # Create index templates if requested
        if not handle_templates_creation(monitor, args):
            return 1

        # Collect metrics
        metrics = monitor.collect_all_metrics()
        if not metrics:
            monitor.logger.error("Failed to collect metrics")
            return 1

        # Send to Elasticsearch or show dry run info
        if args.dry_run:
            return handle_dry_run_output(monitor, metrics, args)
        else:
            monitor.logger.info("Sending metrics to Elasticsearch")
            if monitor.send_to_elasticsearch(metrics):
                monitor.logger.info(
                    "Successfully sent all metrics to Elasticsearch")
                return 0
            else:
                monitor.logger.error(
                    "Failed to send some metrics to Elasticsearch")
                return 1

    except KeyboardInterrupt:
        monitor.logger.info("Script interrupted by user")
        return 1
    except Exception as e:
        monitor.logger.error(f"Unexpected error: {e}")
        return 1


def main():
    """Main function"""
    # Parse config-file argument first to know which config file to load
    config_file_path = os.getenv('CONFIG_FILE', 'config.env')

    # Quick parse to get config file if specified
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument('--config-file', default=config_file_path)
    temp_args, _ = temp_parser.parse_known_args()

    # Load configuration from the specified file
    file_config = load_config_from_file(temp_args.config_file)

    # Set up argument parser
    parser = setup_argument_parser(file_config, temp_args.config_file)
    args = parser.parse_args()

    # Validate required configuration
    if not validate_configuration(args, parser):
        return 1

    # Set up logging and show configuration
    setup_logging_and_show_config(args, file_config)

    # Run the monitor
    return run_monitor(args)


if __name__ == '__main__':
    sys.exit(main())
