from __future__ import annotations

import asyncio
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from unknown_camera.network import NetworkScanner, NetworkScanOptions


class DiscoveryManager:
    """
    Web-facing coordinator for NetworkScanner.

    NetworkScanner remains responsible for network discovery.
    DiscoveryManager only:
      - starts the asynchronous scan;
      - converts discovered devices to JSON-compatible data;
      - publishes events for the web UI.
    """

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._queue: asyncio.Queue[dict[str, Any]] = (
            asyncio.Queue()
        )

    @property
    def running(self) -> bool:
        """Return True while a discovery scan is running."""
        return (
            self._task is not None
            and not self._task.done()
        )

    async def start(
        self,
        options: NetworkScanOptions | None = None,
    ) -> bool:
        """
        Start a discovery scan.

        Returns:
            True  - scan was started.
            False - another scan is already running.
        """

        if self.running:
            return False

        self._clear_queue()

        if options is None:
            options = NetworkScanOptions()

        self._task = asyncio.create_task(
            self._run(options)
        )

        return True

    async def _run(
        self,
        options: NetworkScanOptions,
    ) -> None:
        scanner = NetworkScanner(options)

        await self._publish(
            {
                "type": "scan_started",
            }
        )

        try:
            async for device in scanner.scan():
                await self._publish(
                    {
                        "type": "device_found",
                        "device": self._serialize(device),
                    }
                )

        except asyncio.CancelledError:
            await self._publish(
                {
                    "type": "scan_cancelled",
                }
            )
            raise

        except Exception as exc:
            import traceback

            traceback.print_exc()

            await self._publish(
                {
                    "type": "scan_error",
                    "error": (
                        f"{type(exc).__name__}: {exc}"
                    ),
                }
            )

        else:
            await self._publish(
                {
                    "type": "scan_finished",
                }
            )

    async def _publish(
        self,
        event: dict[str, Any],
    ) -> None:
        await self._queue.put(event)

    async def next_event(self) -> dict[str, Any]:
        """
        Wait for and return the next discovery event.
        """
        return await self._queue.get()

    def _clear_queue(self) -> None:
        """
        Remove events left over from a previous scan.
        """
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    @classmethod
    def _serialize(cls, value: Any) -> Any:
        """
        Convert SDK model objects to JSON-compatible values.
        """

        if value is None:
            return None

        if isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        if isinstance(value, Enum):
            return value.value

        if is_dataclass(value):
            return {
                key: cls._serialize(item)
                for key, item in asdict(value).items()
            }

        if isinstance(value, dict):
            return {
                str(key): cls._serialize(item)
                for key, item in value.items()
            }

        if isinstance(
            value,
            (list, tuple, set),
        ):
            return [
                cls._serialize(item)
                for item in value
            ]

        if hasattr(value, "to_dict"):
            return cls._serialize(
                value.to_dict()
            )

        if hasattr(value, "__dict__"):
            return {
                key: cls._serialize(item)
                for key, item in vars(value).items()
                if not key.startswith("_")
            }

        return str(value)
