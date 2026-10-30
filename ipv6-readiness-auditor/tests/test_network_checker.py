"""
Unit tests for network and TCP connectivity testing.
"""

from unittest.mock import patch, MagicMock
import socket
import pytest
from auditor.network_checker import check_tcp_connection, detect_environment_capabilities


def test_tcp_connection_success():
    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = check_tcp_connection("93.184.216.34", 443, is_ipv6=False)
        assert res["success"] is True
        assert res["error_category"] is None
        assert res["port"] == 443


def test_tcp_connection_refused():
    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection actively refused")
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = check_tcp_connection("198.51.100.1", 8080, is_ipv6=False)
        assert res["success"] is False
        assert res["error_category"] == "Connection Refused"


def test_tcp_connection_timeout():
    with patch("socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = check_tcp_connection("198.51.100.1", 443, is_ipv6=False)
        assert res["success"] is False
        assert res["error_category"] == "Timeout"


def test_tcp_ipv6_env_limitation_skip():
    # When host network lacks outbound IPv6, live tests are classified as environment limitation
    res = check_tcp_connection("2606:2800:220:1:248:1893:25c8:1946", 443, is_ipv6=True, env_v6_capable=False)
    assert res["success"] is False
    assert res["error_category"] == "Environment Limitation"
    assert res["is_env_limitation"] is True
