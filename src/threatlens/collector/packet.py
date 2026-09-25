from dataclasses import dataclass


@dataclass
class NetworkPacket:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str