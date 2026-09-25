"""Detect possible port scans in timestamped sample connection attempts."""

from dataclasses import dataclass
from math import isfinite

from threatlens.collector.packet import NetworkPacket


@dataclass(frozen=True)
class PortScanAlert:
    """Describe suspicious activity without asserting malicious intent."""

    source_ip: str
    destination_ip: str
    protocol: str
    destination_ports: tuple[int, ...]
    timestamp: float
    message: str = "Possible port scan detected."


class PortScanDetector:
    """Count distinct ports in an inclusive rolling window of sample attempts."""

    def __init__(self, port_threshold: int = 5, window_seconds: float = 10.0) -> None:
        """Require a positive integer threshold and finite positive duration."""
        if isinstance(port_threshold, bool) or not isinstance(port_threshold, int) or port_threshold < 1:
            raise ValueError("port_threshold must be a positive integer")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be a finite positive number")

        self._port_threshold = port_threshold
        self._window_seconds = window_seconds
        self._observations: dict[tuple[str, str, str], list[tuple[float, int]]] = {}
        self._alerted: set[tuple[str, str, str]] = set()
        self._last_timestamp: float | None = None

    def process(self, packet: NetworkPacket, timestamp: float) -> PortScanAlert | None:
        """Process an attempt at finite, globally nondecreasing seconds.

        Samples are assumed to represent connection attempts. Observations at
        exactly timestamp minus window_seconds remain inside the window.
        """
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not isfinite(timestamp)
        ):
            raise ValueError("timestamp must be a finite number")
        if self._last_timestamp is not None and timestamp < self._last_timestamp:
            raise ValueError("timestamps must be in nondecreasing order")
        self._last_timestamp = timestamp

        cutoff = timestamp - self._window_seconds
        for key, observations in list(self._observations.items()):
            recent = [(time, port) for time, port in observations if time >= cutoff]
            if len({port for _, port in recent}) < self._port_threshold:
                self._alerted.discard(key)
            if recent:
                self._observations[key] = recent
            else:
                del self._observations[key]

        key = (packet.source_ip, packet.destination_ip, packet.protocol)
        observations = self._observations.setdefault(key, [])
        observations.append((timestamp, packet.destination_port))
        ports = tuple(sorted({port for _, port in observations}))
        if len(ports) < self._port_threshold or key in self._alerted:
            return None

        self._alerted.add(key)
        return PortScanAlert(*key, destination_ports=ports, timestamp=timestamp)
