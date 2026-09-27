from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Iterable


DEFAULT_PORTS: tuple[int, ...] = (
    # HTTP / web
    80,
    81,
    8000,
    8080,
    8081,
    8888,

    # HTTPS
    443,

    # RTSP
    554,
    8554,
    10554,
    10555,

    # Common camera / ONVIF / vendor services
    8001,
    8008,
    8088,
    8899,
    9000,
    10080,
)


@dataclass(slots=True)
class PortScanResult:
    """Result of scanning one TCP port."""

    port: int
    is_open: bool
    response_time: float | None = None
    error: str | None = None


@dataclass(slots=True)
class PortScanSummary:
    """Complete TCP scan result for one network device."""

    target_ip: str
    ports: list[PortScanResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        """Return only open TCP ports."""
        return [
            result.port
            for result in self.ports
            if result.is_open
        ]

    @property
    def closed_ports(self) -> list[int]:
        """Return only ports that were not open."""
        return [
            result.port
            for result in self.ports
            if not result.is_open
        ]


class PortScanner:
    """
    Asynchronous TCP port scanner.

    This class only answers one question:

        Is TCP port X open on host Y?

    It does not identify the protocol running on the port.

    Protocol identification is performed later by specialized probes:
        - HTTPProbe
        - RTSPProbe
        - CGIProbe
        - etc.
    """

    def __init__(
        self,
        target_ip: str,
        ports: Iterable[int] | None = None,
        *,
        timeout: float = 0.5,
        concurrency: int = 64,
    ) -> None:
        self.target_ip = target_ip
        self.ports = tuple(
            ports if ports is not None else DEFAULT_PORTS
        )
        self.timeout = timeout
        self.concurrency = max(1, concurrency)

    async def scan_port(self, port: int) -> PortScanResult:
        """
        Check a single TCP port.
        """

        loop = asyncio.get_running_loop()
        started = loop.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.target_ip,
                    port,
                ),
                timeout=self.timeout,
            )

        except asyncio.TimeoutError:
            return PortScanResult(
                port=port,
                is_open=False,
                response_time=loop.time() - started,
                error="timeout",
            )

        except ConnectionRefusedError:
            return PortScanResult(
                port=port,
                is_open=False,
                response_time=loop.time() - started,
                error="connection_refused",
            )

        except OSError as exc:
            return PortScanResult(
                port=port,
                is_open=False,
                response_time=loop.time() - started,
                error=str(exc),
            )

        except Exception as exc:
            return PortScanResult(
                port=port,
                is_open=False,
                response_time=loop.time() - started,
                error=str(exc),
            )

        else:
            response_time = loop.time() - started

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            return PortScanResult(
                port=port,
                is_open=True,
                response_time=response_time,
            )

    async def scan(self) -> PortScanSummary:
        """
        Scan all configured TCP ports asynchronously.
        """

        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_with_limit(port: int) -> PortScanResult:
            async with semaphore:
                return await self.scan_port(port)

        tasks = [
            asyncio.create_task(
                scan_with_limit(port)
            )
            for port in self.ports
        ]

        results = await asyncio.gather(*tasks)

        # Keep deterministic port order.
        results.sort(key=lambda result: result.port)

        return PortScanSummary(
            target_ip=self.target_ip,
            ports=results,
        )
