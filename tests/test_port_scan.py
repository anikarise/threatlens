"""Exercise detection using controlled samples, without network activity."""

import pytest

from threatlens.collector.packet import NetworkPacket
from threatlens.detection.port_scan import PortScanDetector


def sample(
    port: int,
    source: str = "192.0.2.1",
    destination: str = "198.51.100.2",
    protocol: str = "TCP",
) -> NetworkPacket:
    return NetworkPacket(source, destination, 54321, port, protocol)


def test_threshold_and_alert_details():
    detector = PortScanDetector(port_threshold=3, window_seconds=10)
    assert detector.process(sample(443), 0) is None
    assert detector.process(sample(22), 1) is None
    alert = detector.process(sample(80), 2)
    assert alert is not None
    assert alert.source_ip == "192.0.2.1"
    assert alert.destination_ip == "198.51.100.2"
    assert alert.protocol == "TCP"
    assert alert.destination_ports == (22, 80, 443)
    assert alert.timestamp == 2
    assert alert.message == "Possible port scan detected."


def test_repeated_ports_count_once_even_with_different_source_ports():
    detector = PortScanDetector(port_threshold=2)
    assert detector.process(sample(80), 0) is None
    packet = sample(80)
    packet.source_port = 12345
    assert detector.process(packet, 1) is None
    assert detector.process(sample(443), 2) is not None


@pytest.mark.parametrize("other", [
    sample(443, source="192.0.2.3"),
    sample(443, destination="198.51.100.4"),
    sample(443, protocol="UDP"),
])
def test_groups_are_independent(other: NetworkPacket):
    detector = PortScanDetector(port_threshold=2)
    assert detector.process(sample(80), 0) is None
    assert detector.process(other, 1) is None
    assert detector.process(sample(443), 2) is not None
    other.destination_port = 80
    assert detector.process(other, 3) is not None


@pytest.mark.parametrize("timestamp, expected_alert", [(10, True), (10.01, False)])
def test_inclusive_window_boundary(timestamp: float, expected_alert: bool):
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    detector.process(sample(80), 0)
    assert (detector.process(sample(443), timestamp) is not None) == expected_alert


def test_window_rolls_instead_of_using_fixed_buckets():
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    detector.process(sample(80), 9)
    assert detector.process(sample(443), 11) is not None


def test_suppresses_alerts_until_count_falls_below_threshold():
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    detector.process(sample(80), 0)
    assert detector.process(sample(443), 1) is not None
    assert detector.process(sample(22), 2) is None
    assert detector.process(sample(443), 10.5) is None
    # Only port 443 remains before this new attempt, so detection rearms.
    assert detector.process(sample(25), 13) is not None


def test_new_burst_after_all_observations_expire():
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    detector.process(sample(80), 0)
    assert detector.process(sample(443), 1) is not None
    assert detector.process(sample(80), 20) is None
    assert detector.process(sample(443), 21) is not None


def test_repeated_port_remains_until_its_latest_observation_expires():
    detector = PortScanDetector(port_threshold=2, window_seconds=10)
    detector.process(sample(80), 0)
    detector.process(sample(80), 9)
    assert detector.process(sample(443), 11) is not None


def test_equal_timestamps_are_allowed():
    detector = PortScanDetector(port_threshold=2)
    detector.process(sample(80), 1)
    assert detector.process(sample(443), 1) is not None


def test_out_of_order_timestamp_is_rejected_across_groups_without_changing_state():
    detector = PortScanDetector(port_threshold=2)
    detector.process(sample(80), 5)
    with pytest.raises(ValueError, match="nondecreasing"):
        detector.process(sample(22, source="192.0.2.3"), 4)
    assert detector.process(sample(443), 5) is not None


@pytest.mark.parametrize("threshold", [0, -1, 1.5, True, "5", None])
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="port_threshold"):
        PortScanDetector(port_threshold=threshold)


@pytest.mark.parametrize("window", [0, -1, float("inf"), float("nan"), True, "10", None])
def test_invalid_window(window):
    with pytest.raises(ValueError, match="window_seconds"):
        PortScanDetector(window_seconds=window)


@pytest.mark.parametrize("timestamp", [float("inf"), float("-inf"), float("nan"), True, "1", None])
def test_invalid_timestamp_does_not_change_state(timestamp):
    detector = PortScanDetector(port_threshold=2)
    detector.process(sample(80), 0)
    with pytest.raises(ValueError, match="timestamp"):
        detector.process(sample(22), timestamp)
    assert detector.process(sample(443), 1) is not None


def test_threshold_one_alerts_on_first_attempt():
    assert PortScanDetector(port_threshold=1).process(sample(80), 0) is not None
