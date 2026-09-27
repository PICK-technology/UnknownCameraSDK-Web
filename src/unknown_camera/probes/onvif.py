from __future__ import annotations

import asyncio
import re
import socket
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


WS_DISCOVERY_ADDRESS = "239.255.255.250"
WS_DISCOVERY_PORT = 3702

SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
WS_ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WS_DISCOVERY = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
ONVIF_NETWORK = "http://www.onvif.org/ver10/network/wsdl"


@dataclass
class ONVIFProbeResult:
    """
    Result of an ONVIF WS-Discovery probe.
    """

    confirmed: bool = False

    # IP address of the ONVIF device.
    ip: Optional[str] = None

    # Stable ONVIF device identifier.
    device_uuid: Optional[str] = None

    types: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    xaddrs: list[str] = field(default_factory=list)

    metadata_version: Optional[str] = None

    # UDP source of the received ProbeMatch.
    source_port: Optional[int] = None

    error: Optional[str] = None


class ONVIFProbe:
    """
    ONVIF WS-Discovery probe.

    The probe sends a WS-Discovery Probe request to the standard
    ONVIF multicast address and waits for ProbeMatch responses.
    """

    def __init__(
        self,
        target_ip: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.target_ip = target_ip
        self.timeout = timeout

    def build_message(self) -> bytes:
        """
        Build a WS-Discovery Probe message.
        """

        message_id = f"uuid:{uuid.uuid4()}"

        message = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope
    xmlns:e="{SOAP_ENV}"
    xmlns:w="{WS_ADDRESSING}"
    xmlns:d="{WS_DISCOVERY}"
    xmlns:dn="{ONVIF_NETWORK}">
    <e:Header>
        <w:MessageID>{message_id}</w:MessageID>
        <w:To>
            urn:schemas-xmlsoap-org:ws:2005:04:discovery
        </w:To>
        <w:Action>
            http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
        </w:Action>
    </e:Header>
    <e:Body>
        <d:Probe>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
        </d:Probe>
    </e:Body>
</e:Envelope>
"""

        return message.encode("utf-8")

    @staticmethod
    def _local_name(tag: str) -> str:
        """
        Return XML local name without namespace.
        """

        if "}" in tag:
            return tag.rsplit("}", 1)[1]

        return tag

    @classmethod
    def _find_elements(
        cls,
        root: ET.Element,
        name: str,
    ) -> list[ET.Element]:
        """
        Find XML elements by local name.

        This avoids depending on a particular namespace prefix.
        """

        return [
            element
            for element in root.iter()
            if cls._local_name(element.tag) == name
        ]


    def _process_response(
        self,
        data: bytes,
        ip: str | None = None,
        port: int | None = None,
    ) -> ONVIFProbeResult:
        """
        Process one WS-Discovery response.

        This method is intentionally kept as the internal response
        processing API used by the unit tests and discovery layer.
        """

        result = ONVIFProbeResult(
            ip=ip,
            source_port=port,
        )

        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            result.error = "invalid_xml"
            return result

        probe_matches = [
            element
            for element in root.iter()
            if self._local_name(element.tag) == "ProbeMatch"
        ]

        if not probe_matches:
            result.error = "no_probe_match"
            return result

        probe_match = probe_matches[0]

        # ---------------------------------------------------------
        # Device UUID
        # ---------------------------------------------------------

        for element in probe_match.iter():
            if self._local_name(element.tag) == "Address":
                if element.text:
                    result.device_uuid = element.text.strip()
                break

        # ---------------------------------------------------------
        # Types
        # ---------------------------------------------------------

        for element in probe_match.iter():
            if self._local_name(element.tag) == "Types":
                if element.text:
                    result.types = element.text.split()
                break

        # ---------------------------------------------------------
        # Scopes
        # ---------------------------------------------------------

        for element in probe_match.iter():
            if self._local_name(element.tag) == "Scopes":
                if element.text:
                    result.scopes = element.text.split()
                break

        # ---------------------------------------------------------
        # XAddrs
        # ---------------------------------------------------------

        for element in probe_match.iter():
            if self._local_name(element.tag) == "XAddrs":
                if element.text:
                    result.xaddrs = element.text.split()
                break

        # ---------------------------------------------------------
        # MetadataVersion
        # ---------------------------------------------------------

        for element in probe_match.iter():
            if self._local_name(element.tag) == "MetadataVersion":
                if element.text:
                    result.metadata_version = element.text.strip()
                break

        result.confirmed = True

        return result

    @classmethod
    def parse_response(
        cls,
        data: bytes,
        source_ip: str | None = None,
        source_port: int | None = None,
    ) -> ONVIFProbeResult:
        """
        Compatibility helper for parsing a single response.
        """

        probe = cls()

        return probe._process_response(
            data,
            ip=source_ip,
            port=source_port,
        )

    async def probe(self) -> ONVIFProbeResult:
        """
        Send WS-Discovery Probe and wait for responses.
        """

        loop = asyncio.get_running_loop()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
        )

        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )

            # Bind to an ephemeral UDP port.
            sock.bind(("0.0.0.0", 0))

            # Let the OS choose the appropriate multicast interface.
            # This is important on Windows where multiple network
            # interfaces may exist.
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton("0.0.0.0"),
            )

            sock.setblocking(False)

            message = self.build_message()

            await loop.sock_sendto(
                sock,
                message,
                (
                    WS_DISCOVERY_ADDRESS,
                    WS_DISCOVERY_PORT,
                ),
            )

            deadline = loop.time() + self.timeout

            while True:
                remaining = deadline - loop.time()

                if remaining <= 0:
                    return ONVIFProbeResult(
                        confirmed=False,
                        error="timeout",
                    )

                try:
                    data, address = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 65535),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    return ONVIFProbeResult(
                        confirmed=False,
                        error="timeout",
                    )

                source_ip, source_port = address

                result = self._process_response(
                    data,
                    ip=source_ip,
                    port=source_port,
                )

                if not result.confirmed:
                    continue

                # If target_ip was specified, ignore responses from
                # other devices.
                if (
                    self.target_ip is not None
                    and source_ip != self.target_ip
                ):
                    continue

                return result

        except OSError as exc:
            return ONVIFProbeResult(
                confirmed=False,
                error=f"{type(exc).__name__}: {exc}",
            )

        finally:
            sock.close()
