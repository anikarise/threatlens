import pytest

from threatlens.collector.packet import NetworkPacket


def test_packet_stores_fields():
    packet = NetworkPacket(
        source_ip="192.0.2.1",
        destination_ip="198.51.100.2",
        source_port=54321,
        destination_port=443,
        protocol="TCP",
    )

    assert packet.source_ip == "192.0.2.1"
    assert packet.destination_ip == "198.51.100.2"
    assert packet.source_port == 54321
    assert packet.destination_port == 443
    assert packet.protocol == "TCP"


def test_packets_with_same_fields_are_equal():
    packet = NetworkPacket("192.0.2.1", "198.51.100.2", 54321, 443, "TCP")
    other = NetworkPacket("192.0.2.1", "198.51.100.2", 54321, 443, "TCP")

    assert packet == other


def test_packets_with_different_fields_are_not_equal():
    packet = NetworkPacket("192.0.2.1", "198.51.100.2", 54321, 443, "TCP")
    other = NetworkPacket("192.0.2.1", "198.51.100.2", 54321, 80, "TCP")

    assert packet != other


def test_packet_requires_all_fields():
    with pytest.raises(TypeError):
        NetworkPacket(
            source_ip="192.0.2.1",
            destination_ip="198.51.100.2",
            source_port=54321,
            destination_port=443,
        )
