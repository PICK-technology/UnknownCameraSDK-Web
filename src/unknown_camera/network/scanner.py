from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import AsyncIterator

from unknown_camera.models import NetworkDevice


@dataclass(slots=True)
class NetworkScanOptions:
    subnet: str | None = None
    ping_timeout: float = 0.8
    concurrency: int = 64
    include_local_host: bool = True


class NetworkScanner:
    """
    Discover devices on the local IPv4 network.

    Discovery is intentionally limited to finding network devices.
    Camera identification is performed by separate probes.
    """

    def __init__(
        self,
        options: NetworkScanOptions | None = None,
    ) -> None:
        self.options = options or NetworkScanOptions()

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def _get_subnet(self) -> ipaddress.IPv4Network:
        if self.options.subnet:
            network = ipaddress.ip_network(
                self.options.subnet,
                strict=False,
            )

            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("Only IPv4 networks are supported")

            return network

        local_ip = self._get_local_ip()

        return ipaddress.ip_network(
            f"{local_ip}/24",
            strict=False,
        )

    @staticmethod
    def _get_local_ip() -> str:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:
            sock.connect(("192.0.2.1", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # Device identity
    # ------------------------------------------------------------------

    @staticmethod
    def _make_device_id(ip: str) -> str:
        return f"network:{ip}"

    # ------------------------------------------------------------------
    # ICMP
    # ------------------------------------------------------------------

    async def _ping(self, ip: str) -> bool:
        """
        Perform a single ICMP echo request.

        The subprocess is executed in a worker thread so that
        discovery works with both asyncio and the Windows event
        loop used by the web server.
        """

        if platform.system().lower() == "windows":
            command = [
                "ping",
                "-n",
                "1",
                "-w",
                str(
                    int(
                        self.options.ping_timeout * 1000
                    )
                ),
                ip,
            ]
        else:
            command = [
                "ping",
                "-c",
                "1",
                "-W",
                str(
                    max(
                        1,
                        int(
                            self.options.ping_timeout
                        ),
                    )
                ),
                ip,
            ]

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=self.options.ping_timeout + 1.0,
            )

            return result.returncode == 0

        except (
            subprocess.TimeoutExpired,
            OSError,
        ):
            return False

    # ------------------------------------------------------------------
    # Windows ARP
    # ------------------------------------------------------------------

    async def _read_arp_table(
        self,
        network: ipaddress.IPv4Network,
    ) -> dict[str, str]:
        """
        Read the Windows ARP table.

        The subprocess itself is executed in a worker thread because
        asyncio subprocess transports are not available in all event
        loop/server configurations on Windows.

        Only real unicast IPv4 addresses belonging to the
        scanned network are accepted.
        """

        if platform.system().lower() != "windows":
            return {}

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "arp",
                    "-a",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        except OSError:
            return {}

        text = result.stdout.decode(
            "cp866",
            errors="replace",
        )

        return self._parse_windows_arp(
            text,
            network,
        )

    @staticmethod
    def _parse_windows_arp(
        output: str,
        network: ipaddress.IPv4Network,
    ) -> dict[str, str]:
        """
        Parse Windows `arp -a` output.

        Only real unicast IPv4 hosts inside the scanned
        network are returned.

        Broadcast, multicast and other non-host addresses
        are ignored.
        """

        result: dict[str, str] = {}

        pattern = re.compile(
            r"^\s*"
            r"(\d{1,3}(?:\.\d{1,3}){3})"
            r"\s+"
            r"([0-9a-fA-F]{2}"
            r"(?:-[0-9a-fA-F]{2}){5})"
            r"\s+"
            r"(\w+)"
            r"\s*$"
        )

        for line in output.splitlines():
            match = pattern.match(line)

            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2).upper()
            entry_type = match.group(3).lower()

            # Ignore empty/invalid MAC entries.
            if mac == "00-00-00-00-00-00":
                continue

            if entry_type not in {
                "dynamic",
                "static",
            }:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue

            # We only work with IPv4.
            if not isinstance(
                ip_obj,
                ipaddress.IPv4Address,
            ):
                continue

            # Ignore addresses outside the scanned network.
            if ip_obj not in network:
                continue

            # Ignore network and broadcast addresses.
            if ip_obj == network.network_address:
                continue

            if ip_obj == network.broadcast_address:
                continue

            result[ip] = mac

        return result

    # ------------------------------------------------------------------
    # Active neighbor discovery
    # ------------------------------------------------------------------

    async def _probe_for_arp(
        self,
        ip: str,
        semaphore: asyncio.Semaphore,
    ) -> bool:
        """
        Cause Windows to resolve the neighbor through ARP.

        The important point is that we do NOT require ICMP success.
        """

        # print(
        #     "ARP PROBE START:",
        #     ip,
        #     flush=True,
        # )

        async with semaphore:

            # print(
            #     "ARP PROBE DONE:",
            #     ip,
            #     flush=True,
            # )

            return await self._ping(ip)

    async def _active_neighbor_discovery(
        self,
        network: ipaddress.IPv4Network,
    ) -> dict[str, str]:
        """
        Actively populate the Windows ARP table.

        ICMP success is not required for a device to be considered
        discovered. The subsequent ARP table is the source of truth.
        """

        semaphore = asyncio.Semaphore(
            self.options.concurrency
        )

        hosts = [
            str(ip)
            for ip in network.hosts()
        ]

        if not self.options.include_local_host:
            local_ip = self._get_local_ip()

            hosts = [
                ip
                for ip in hosts
                if ip != local_ip
            ]

        tasks = [
            asyncio.create_task(
                self._probe_for_arp(
                    ip,
                    semaphore,
                )
            )
            for ip in hosts
        ]

        if tasks:
            await asyncio.gather(
                *tasks,
                return_exceptions=True,
            )

        return await self._read_arp_table(
            network,
        )

    # ------------------------------------------------------------------
    # Hostname
    # ------------------------------------------------------------------

    @staticmethod
    async def _resolve_hostname(
        ip: str,
    ) -> str | None:
        try:
            hostname, _, _ = await asyncio.to_thread(
                socket.gethostbyaddr,
                ip,
            )

            return hostname

        except (
            socket.herror,
            socket.gaierror,
            OSError,
        ):
            return None

    # ------------------------------------------------------------------
    # Device creation
    # ------------------------------------------------------------------

    async def _create_device(
        self,
        ip: str,
        mac: str | None,
        icmp_reachable: bool,
    ) -> NetworkDevice:

        hostname = await self._resolve_hostname(ip)

        sources: list[str] = []

        if mac:
            sources.append("arp")

        if icmp_reachable:
            sources.append("icmp")

        return NetworkDevice(
            id=self._make_device_id(ip),
            ip=ip,
            mac=mac,
            hostname=hostname,
            discovery_sources=sources,
        )

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    async def scan(
        self,
    ) -> AsyncIterator[NetworkDevice]:
        """
        Scan the local network and yield NetworkDevice objects.

        Devices are yielded incrementally.
        """

        print(
            "SCANNER: scan() entered",
            flush=True,
        )

        network = self._get_subnet()

        print(
            "SCANNER: subnet =",
            network,
            flush=True,
        )

        print(
            "SCANNER: before active neighbor discovery",
            flush=True,
        )

        print(
            "SCANNER: scan task:",
            asyncio.current_task(),
            flush=True,
        )

        print(
            "SCANNER: event loop:",
            asyncio.get_running_loop(),
            flush=True,
        )

        print(
            "SCANNER: loop type:",
            type(asyncio.get_running_loop()),
            flush=True,
        )

        arp_devices = await self._active_neighbor_discovery(
            network
        )

        print(
            "SCANNER: after active neighbor discovery:",
            len(arp_devices),
            flush=True,
        )

        # --------------------------------------------------------------
        # Second stage:
        # ICMP scan
        # --------------------------------------------------------------

        semaphore = asyncio.Semaphore(
            self.options.concurrency
        )

        hosts = [
            str(ip)
            for ip in network.hosts()
        ]

        local_ip = self._get_local_ip()

        if not self.options.include_local_host:
            hosts = [
                ip
                for ip in hosts
                if ip != local_ip
            ]

        async def probe(ip: str):
            async with semaphore:
                reachable = await self._ping(ip)

                return ip, reachable

        tasks = [
            asyncio.create_task(
                probe(ip)
            )
            for ip in hosts
        ]

        icmp_results: dict[str, bool] = {}

        for task in asyncio.as_completed(tasks):
            ip, reachable = await task

            if reachable:
                icmp_results[ip] = True

        # --------------------------------------------------------------
        # Merge
        # --------------------------------------------------------------

        discovered_ips = (
            set(arp_devices)
            | set(icmp_results)
        )

        for ip in sorted(
            discovered_ips,
            key=ipaddress.ip_address,
        ):
            device = await self._create_device(
                ip=ip,
                mac=arp_devices.get(ip),
                icmp_reachable=icmp_results.get(
                    ip,
                    False,
                ),
            )

            yield device
