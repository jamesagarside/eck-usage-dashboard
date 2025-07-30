#!/usr/bin/env python3
"""
Tests for ECK Usage Monitor

Basic pytest tests for the ECK usage monitoring functionality.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch

# Import the module under test
from eck_usage_monitor import (
    ECKUsageMonitor,
    load_config_from_file,
    str_to_bool,
    setup_argument_parser,
    validate_configuration,
    handle_templates_creation,
    handle_dry_run_output
)


class TestConfigLoading:
    """Test configuration loading functionality"""

    def test_load_config_from_nonexistent_file(self):
        """Test loading config from non-existent file returns empty dict"""
        result = load_config_from_file("nonexistent.env")
        assert result == {}

    def test_load_config_from_file_basic(self):
        """Test loading basic configuration from file"""
        config_content = """
# Test configuration
ELASTICSEARCH_URL=https://test.elastic.co:9200
ELASTICSEARCH_API_KEY=test_key_123
INDEX_PREFIX=test-eck
CREATE_TEMPLATES=true
VERBOSE=false
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(config_content)
            f.flush()

            try:
                result = load_config_from_file(f.name)
                assert result['ELASTICSEARCH_URL'] == 'https://test.elastic.co:9200'
                assert result['ELASTICSEARCH_API_KEY'] == 'test_key_123'
                assert result['INDEX_PREFIX'] == 'test-eck'
                assert result['CREATE_TEMPLATES'] == 'true'
                assert result['VERBOSE'] == 'false'
            finally:
                os.unlink(f.name)

    def test_load_config_handles_quotes(self):
        """Test that config loader handles quoted values"""
        config_content = """
ELASTICSEARCH_URL="https://test.elastic.co:9200"
ELASTICSEARCH_API_KEY='test_key_123'
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(config_content)
            f.flush()

            try:
                result = load_config_from_file(f.name)
                assert result['ELASTICSEARCH_URL'] == 'https://test.elastic.co:9200'
                assert result['ELASTICSEARCH_API_KEY'] == 'test_key_123'
            finally:
                os.unlink(f.name)

    def test_load_config_skips_comments_and_empty_lines(self):
        """Test that config loader skips comments and empty lines"""
        config_content = """
# This is a comment
ELASTICSEARCH_URL=https://test.elastic.co:9200

# Another comment
ELASTICSEARCH_API_KEY=test_key_123

invalid_line_without_equals
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(config_content)
            f.flush()

            try:
                result = load_config_from_file(f.name)
                assert len(result) == 2
                assert result['ELASTICSEARCH_URL'] == 'https://test.elastic.co:9200'
                assert result['ELASTICSEARCH_API_KEY'] == 'test_key_123'
            finally:
                os.unlink(f.name)

    def test_str_to_bool_conversions(self):
        """Test string to boolean conversions"""
        assert str_to_bool('true') is True
        assert str_to_bool('True') is True
        assert str_to_bool('TRUE') is True
        assert str_to_bool('1') is True
        assert str_to_bool('yes') is True
        assert str_to_bool('on') is True

        assert str_to_bool('false') is False
        assert str_to_bool('False') is False
        assert str_to_bool('0') is False
        assert str_to_bool('no') is False
        assert str_to_bool('off') is False
        assert str_to_bool('anything_else') is False

        # Test with actual boolean values
        assert str_to_bool(True) is True
        assert str_to_bool(False) is False


class TestECKUsageMonitor:
    """Test ECK Usage Monitor class"""

    def test_init(self):
        """Test ECKUsageMonitor initialization"""
        monitor = ECKUsageMonitor(
            elasticsearch_url="https://test.elastic.co:9200",
            api_key="test_key",
            index_prefix="test-eck"
        )

        assert monitor.elasticsearch_url == "https://test.elastic.co:9200"
        assert monitor.api_key == "test_key"
        assert monitor.index_prefix == "test-eck"
        assert monitor.session is not None
        assert monitor.logger is not None

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from Elasticsearch URL"""
        monitor = ECKUsageMonitor(
            elasticsearch_url="https://test.elastic.co:9200/",
            api_key="test_key"
        )

        assert monitor.elasticsearch_url == "https://test.elastic.co:9200"

    @patch('eck_usage_monitor.subprocess.run')
    def test_run_kubectl_command_success(self, mock_run):
        """Test successful kubectl command execution"""
        mock_result = Mock()
        mock_result.stdout = '{"items": [{"name": "test"}]}'
        mock_run.return_value = mock_result

        monitor = ECKUsageMonitor("https://test.co", "key")
        result = monitor.run_kubectl_command(['kubectl', 'get', 'pods'])

        assert result == {"items": [{"name": "test"}]}
        mock_run.assert_called_once_with(
            ['kubectl', 'get', 'pods'],
            capture_output=True,
            text=True,
            check=True
        )

    @patch('eck_usage_monitor.subprocess.run')
    def test_run_kubectl_command_failure(self, mock_run):
        """Test kubectl command execution failure"""
        from subprocess import CalledProcessError
        mock_run.side_effect = CalledProcessError(
            1, 'kubectl', stderr="Command failed")

        monitor = ECKUsageMonitor("https://test.co", "key")
        result = monitor.run_kubectl_command(['kubectl', 'get', 'pods'])

        assert result is None

    def test_parse_memory_to_bytes(self):
        """Test memory string parsing to bytes"""
        monitor = ECKUsageMonitor("https://test.co", "key")

        assert monitor._parse_memory_to_bytes("1Gi") == 1024 ** 3
        assert monitor._parse_memory_to_bytes("512Mi") == 512 * 1024 ** 2
        assert monitor._parse_memory_to_bytes("1024Ki") == 1024 * 1024
        assert monitor._parse_memory_to_bytes("1G") == 1000 ** 3
        assert monitor._parse_memory_to_bytes("500M") == 500 * 1000 ** 2
        assert monitor._parse_memory_to_bytes("1000") == 1000
        assert monitor._parse_memory_to_bytes("0") == 0
        assert monitor._parse_memory_to_bytes("") == 0
        assert monitor._parse_memory_to_bytes("invalid") == 0

    def test_parse_cpu_to_cores(self):
        """Test CPU string parsing to cores"""
        monitor = ECKUsageMonitor("https://test.co", "key")

        assert monitor._parse_cpu_to_cores("1000m") == 1.0
        assert monitor._parse_cpu_to_cores("500m") == 0.5
        assert monitor._parse_cpu_to_cores("2") == 2.0
        assert monitor._parse_cpu_to_cores("1.5") == 1.5
        assert monitor._parse_cpu_to_cores("0") == 0.0
        assert monitor._parse_cpu_to_cores("") == 0.0
        assert monitor._parse_cpu_to_cores("invalid") == 0.0

    @patch('eck_usage_monitor.requests.Session.post')
    def test_send_document_success(self, mock_post):
        """Test successful document sending"""
        mock_response = Mock()
        mock_response.json.return_value = {"result": "created"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        monitor = ECKUsageMonitor("https://test.co", "key")
        result = monitor._send_document("test-index", {"test": "doc"})

        assert result is True

    @patch('eck_usage_monitor.requests.Session.post')
    def test_send_document_failure(self, mock_post):
        """Test document sending failure"""
        import requests
        mock_post.side_effect = requests.exceptions.RequestException(
            "Network error")

        monitor = ECKUsageMonitor("https://test.co", "key")
        result = monitor._send_document("test-index", {"test": "doc"})

        assert result is False


class TestArgumentParsing:
    """Test argument parsing and validation"""

    def test_setup_argument_parser_with_config(self):
        """Test argument parser setup with config file values"""
        file_config = {
            'ELASTICSEARCH_URL': 'https://config.elastic.co:9200',
            'ELASTICSEARCH_API_KEY': 'config_key',
            'INDEX_PREFIX': 'config-eck',
            'VERBOSE': 'true'
        }

        parser = setup_argument_parser(file_config, 'test.env')

        # Parse empty args to get defaults
        args = parser.parse_args([])

        assert args.elasticsearch_url == 'https://config.elastic.co:9200'
        assert args.api_key == 'config_key'
        assert args.index_prefix == 'config-eck'
        assert args.verbose is True

    def test_setup_argument_parser_without_config(self):
        """Test argument parser setup without config file"""
        file_config = {}

        parser = setup_argument_parser(file_config, 'test.env')

        # Parse empty args to get defaults
        args = parser.parse_args([])

        assert args.elasticsearch_url is None
        assert args.api_key is None
        assert args.index_prefix == 'eck-usage'  # Default value
        assert args.verbose is False

    def test_validate_configuration_success(self):
        """Test successful configuration validation"""
        mock_args = Mock()
        mock_args.elasticsearch_url = 'https://test.co'
        mock_args.api_key = 'test_key'
        mock_parser = Mock()

        result = validate_configuration(mock_args, mock_parser)

        assert result is True
        mock_parser.print_help.assert_not_called()

    def test_validate_configuration_missing_url(self):
        """Test configuration validation with missing URL"""
        mock_args = Mock()
        mock_args.elasticsearch_url = None
        mock_args.api_key = 'test_key'
        mock_parser = Mock()

        result = validate_configuration(mock_args, mock_parser)

        assert result is False
        mock_parser.print_help.assert_called_once()

    def test_validate_configuration_missing_api_key(self):
        """Test configuration validation with missing API key"""
        mock_args = Mock()
        mock_args.elasticsearch_url = 'https://test.co'
        mock_args.api_key = None
        mock_parser = Mock()

        result = validate_configuration(mock_args, mock_parser)

        assert result is False
        mock_parser.print_help.assert_called_once()


class TestMonitorFunctions:
    """Test monitor utility functions"""

    def test_handle_templates_creation_normal_mode(self):
        """Test template creation in normal mode"""
        mock_monitor = Mock()
        mock_monitor.create_index_templates.return_value = True
        mock_args = Mock()
        mock_args.create_templates = True
        mock_args.dry_run = False

        result = handle_templates_creation(mock_monitor, mock_args)

        assert result is True
        mock_monitor.create_index_templates.assert_called_once()

    def test_handle_templates_creation_dry_run_mode(self):
        """Test template creation in dry run mode"""
        mock_monitor = Mock()
        mock_args = Mock()
        mock_args.create_templates = True
        mock_args.dry_run = True

        result = handle_templates_creation(mock_monitor, mock_args)

        assert result is True
        mock_monitor.create_index_templates.assert_not_called()

    def test_handle_templates_creation_disabled(self):
        """Test when template creation is disabled"""
        mock_monitor = Mock()
        mock_args = Mock()
        mock_args.create_templates = False
        mock_args.dry_run = False

        result = handle_templates_creation(mock_monitor, mock_args)

        assert result is True
        mock_monitor.create_index_templates.assert_not_called()

    def test_handle_dry_run_output(self):
        """Test dry run output handling"""
        mock_monitor = Mock()
        mock_args = Mock()
        mock_args.verbose = True

        metrics = {
            'summary': {
                'total_components': 5,
                'components_by_type': {'elasticsearch': {'deployments': 1, 'instances': 3}}
            },
            'components': [{'test': 'component'}]
        }

        result = handle_dry_run_output(mock_monitor, metrics, mock_args)

        assert result == 0


class TestECSDocumentStructure:
    """Test ECS document structure creation"""

    def test_create_base_ecs_document(self):
        """Test base ECS document creation"""
        monitor = ECKUsageMonitor("https://test.co", "key")

        metadata = {
            'name': 'test-elasticsearch',
            'namespace': 'elastic-system',
            'uid': 'test-uid-123',
            'generation': 1,
            'labels': {'app': 'elasticsearch'},
            'annotations': {'version': '8.0.0'}
        }

        spec = {'version': '8.11.0'}
        status = {'health': 'green', 'phase': 'Ready'}

        with patch.object(monitor, '_get_cluster_name', return_value='test-cluster'), \
                patch.object(monitor, '_get_kubernetes_version', return_value='v1.28.0'):

            doc = monitor._create_base_ecs_document(
                metadata, spec, status, 'elasticsearch')

        # Test ECS structure
        assert doc['ecs']['version'] == '8.0.0'
        assert doc['event']['kind'] == 'metric'
        assert doc['event']['dataset'] == 'eck.usage'

        # Test orchestrator fields
        assert doc['orchestrator']['type'] == 'kubernetes'
        assert doc['orchestrator']['namespace'] == 'elastic-system'
        assert doc['orchestrator']['resource']['name'] == 'test-elasticsearch'
        assert doc['orchestrator']['resource']['type'] == 'elasticsearch'
        assert doc['orchestrator']['cluster']['name'] == 'test-cluster'

        # Test service fields
        assert doc['service']['name'] == 'eck-elasticsearch'
        assert doc['service']['type'] == 'elasticsearch'
        assert doc['service']['version'] == '8.11.0'

        # Test ECK fields
        assert doc['eck']['deployment']['name'] == 'test-elasticsearch'
        assert doc['eck']['deployment']['namespace'] == 'elastic-system'
        assert doc['eck']['status']['health'] == 'green'
        assert doc['eck']['status']['phase'] == 'Ready'


if __name__ == '__main__':
    pytest.main([__file__])
