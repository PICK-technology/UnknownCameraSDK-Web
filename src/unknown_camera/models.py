from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class DeviceClassification(str, Enum):
    """Current classification of a network device."""

    UNKNOWN = "unknown"
    CAMERA = "camera"


class ServiceType(str, Enum):
    """Known network services relevant to camera discovery."""

    HTTP = "http"
    HTTPS = "https"
    CGI = "cgi"
    ONVIF = "onvif"
    RTSP = "rtsp"


class ProbeStatus(str, Enum):
    """Result of an individual service/network probe."""

    UNKNOWN = "unknown"
    CHECKING = "checking"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(slots=True)
class PortInfo:
    """Information about a discovered TCP/UDP port."""

    port: int
    protocol: str = "tcp"
    service: Optional[ServiceType] = None
    status: ProbeStatus = ProbeStatus.UNKNOWN
    evidence: Optional[str] = None


@dataclass(slots=True)
class ServiceInfo:
    """Information about a detected network service."""

    type: ServiceType
    status: ProbeStatus = ProbeStatus.UNKNOWN
    port: Optional[int] = None
    endpoint: Optional[str] = None
    evidence: Optional[str] = None


@dataclass(slots=True)
class DeviceIdentity:
    """
    Device identity information.

    IP address is deliberately not part of the identity.
    Network location can change while the physical device remains the same.
    """

    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    device_id: Optional[str] = None
    hardware_id: Optional[str] = None
    firmware: Optional[str] = None
    system_version: Optional[str] = None


@dataclass(slots=True)
class NetworkDevice:
    """
    A device discovered on the local network.

    Every discovered network device is represented by this class.
    A device becomes a camera only after sufficient evidence is collected.
    """

    id: str

    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None

    classification: DeviceClassification = DeviceClassification.UNKNOWN

    identity: DeviceIdentity = field(default_factory=DeviceIdentity)

    ports: list[PortInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)

    discovery_sources: list[str] = field(default_factory=list)

    discovered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    last_seen_at: Optional[datetime] = None

    def is_camera(self) -> bool:
        """Return True if the device is currently classified as a camera."""

        return self.classification is DeviceClassification.CAMERA

    def get_service(self, service_type: ServiceType) -> Optional[ServiceInfo]:
        """Return the first service of the requested type."""

        for service in self.services:
            if service.type is service_type:
                return service

        return None

    def has_service(self, service_type: ServiceType) -> bool:
        """Return True when a service is currently known."""

        service = self.get_service(service_type)

        return service is not None and service.status is ProbeStatus.AVAILABLE

    def add_service(self, service: ServiceInfo) -> None:
        """
        Add or update a service.

        A service is identified by its type and port.
        """

        for index, existing in enumerate(self.services):
            if (
                existing.type is service.type
                and existing.port == service.port
            ):
                self.services[index] = service
                return

        self.services.append(service)

    def add_port(self, port: PortInfo) -> None:
        """Add or update port information."""

        for index, existing in enumerate(self.ports):
            if (
                existing.port == port.port
                and existing.protocol == port.protocol
            ):
                self.ports[index] = port
                return

        self.ports.append(port)

    def add_discovery_source(self, source: str) -> None:
        """Add a discovery source without creating duplicates."""

        if source not in self.discovery_sources:
            self.discovery_sources.append(source)

    def mark_camera(self) -> None:
        """Classify this device as a camera."""

        self.classification = DeviceClassification.CAMERA

    def touch(self) -> None:
        """Update the last-seen timestamp."""

        self.last_seen_at = datetime.now(timezone.utc)
