from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RTSPProbeResult:
    ip: str
    port: int

    confirmed: bool = False
    reachable: bool = False

    status_code: Optional[int] = None
    status_text: str = ""

    server: Optional[str] = None

    public_methods: list[str] = field(default_factory=list)

    content_base: Optional[str] = None
    content_location: Optional[str] = None

    has_video: bool = False
    video_codecs: list[str] = field(default_factory=list)

    has_audio: bool = False
    audio_codecs: list[str] = field(default_factory=list)

    sdp: Optional[str] = None

    error: Optional[str] = None


class RTSPProbe:
    """
    Lightweight RTSP probe.

    The probe does not attempt to start a media stream.
    It verifies that a TCP service speaks RTSP and that
    DESCRIBE returns useful SDP information.
    """

    def __init__(
        self,
        ip: str,
        port: int,
        *,
        timeout: float = 2.0,
    ) -> None:
        self.ip = ip
        self.port = port
        self.timeout = max(float(timeout), 0.1)

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

        self._cseq = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def probe(self) -> RTSPProbeResult:
        result = RTSPProbeResult(
            ip=self.ip,
            port=self.port,
        )

        try:
            await self._connect()

            result.reachable = True

            # ----------------------------------------------------------
            # OPTIONS
            # ----------------------------------------------------------

            options = await self._request(
                method="OPTIONS",
                uri=self._rtsp_uri(),
            )

            if options is None:
                result.error = "no_response"
                return result

            status_code, status_text, headers, _ = options

            result.status_code = status_code
            result.status_text = status_text

            result.server = headers.get("server")

            public = headers.get("public", "")
            result.public_methods = self._parse_methods(public)

            if not self._is_rtsp_response(status_code, status_text):
                result.error = "not_rtsp"
                return result

            # A valid RTSP response is already strong evidence.
            result.confirmed = True

            # ----------------------------------------------------------
            # DESCRIBE
            # ----------------------------------------------------------

            describe = await self._request(
                method="DESCRIBE",
                uri=self._rtsp_uri(),
                headers={
                    "Accept": "application/sdp",
                },
            )

            if describe is None:
                return result

            (
                describe_status,
                describe_status_text,
                describe_headers,
                body,
            ) = describe

            # Keep the successful OPTIONS status unless DESCRIBE
            # gives us a useful RTSP response as well.
            if describe_status:
                result.status_code = describe_status
                result.status_text = describe_status_text

            if describe_headers.get("content-base"):
                result.content_base = describe_headers["content-base"]

            if describe_headers.get("content-location"):
                result.content_location = describe_headers["content-location"]

            if body:
                result.sdp = body
                self._parse_sdp(body, result)

            return result

        except asyncio.TimeoutError:
            result.error = "timeout"
            return result

        except ConnectionRefusedError:
            result.error = "connection_refused"
            return result

        except ConnectionResetError:
            result.error = "connection_reset"
            return result

        except OSError as exc:
            result.error = f"os_error: {exc}"
            return result

        except Exception as exc:
            # Probe code must never break the scanner.
            result.error = f"error: {exc}"
            return result

        finally:
            await self._close()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def _connect(self) -> None:
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.ip,
                self.port,
            ),
            timeout=self.timeout,
        )

    async def _close(self) -> None:
        writer = self._writer

        self._reader = None
        self._writer = None

        if writer is None:
            return

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # RTSP
    # ------------------------------------------------------------------

    def _rtsp_uri(self) -> str:
        return f"rtsp://{self.ip}:{self.port}/"

    async def _request(
        self,
        *,
        method: str,
        uri: str,
        headers: Optional[dict[str, str]] = None,
    ) -> tuple[int, str, dict[str, str], str] | None:

        if self._reader is None or self._writer is None:
            return None

        self._cseq += 1

        request_headers = {
            "CSeq": str(self._cseq),
            "User-Agent": "UnknownCameraSDK",
        }

        if headers:
            request_headers.update(headers)

        lines = [
            f"{method} {uri} RTSP/1.0",
        ]

        for name, value in request_headers.items():
            lines.append(f"{name}: {value}")

        request = "\r\n".join(lines) + "\r\n\r\n"

        self._writer.write(request.encode("ascii"))

        await asyncio.wait_for(
            self._writer.drain(),
            timeout=self.timeout,
        )

        return await self._read_response()

    async def _read_response(
        self,
    ) -> tuple[int, str, dict[str, str], str] | None:

        if self._reader is None:
            return None

        # Read RTSP headers.
        header_data = await asyncio.wait_for(
            self._reader.readuntil(b"\r\n\r\n"),
            timeout=self.timeout,
        )

        header_text = header_data.decode(
            "utf-8",
            errors="replace",
        )

        lines = header_text.split("\r\n")

        if not lines:
            return None

        status_line = lines[0]

        match = re.match(
            r"^RTSP/(\d+\.\d+)\s+(\d{3})(?:\s+(.*))?$",
            status_line,
            re.IGNORECASE,
        )

        if not match:
            return None

        status_code = int(match.group(2))
        status_text = match.group(3) or ""

        headers: dict[str, str] = {}

        for line in lines[1:]:
            if not line or ":" not in line:
                continue

            name, value = line.split(":", 1)

            headers[name.strip().lower()] = value.strip()

        body = ""

        content_length = self._get_content_length(headers)

        if content_length > 0:
            body_data = await asyncio.wait_for(
                self._reader.readexactly(content_length),
                timeout=self.timeout,
            )

            body = body_data.decode(
                "utf-8",
                errors="replace",
            )

        return (
            status_code,
            status_text,
            headers,
            body,
        )

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rtsp_response(
        status_code: int,
        status_text: str,
    ) -> bool:
        return 100 <= status_code <= 599

    @staticmethod
    def _get_content_length(
        headers: dict[str, str],
    ) -> int:
        value = headers.get("content-length")

        if not value:
            return 0

        try:
            return max(int(value), 0)
        except ValueError:
            return 0

    @staticmethod
    def _parse_methods(
        value: str,
    ) -> list[str]:
        if not value:
            return []

        result: list[str] = []

        for method in value.split(","):
            method = method.strip()

            if method and method not in result:
                result.append(method)

        return result

    # ------------------------------------------------------------------
    # SDP parsing
    # ------------------------------------------------------------------

    @classmethod
    def _parse_sdp(
        cls,
        sdp: str,
        result: RTSPProbeResult,
    ) -> None:

        current_media: Optional[str] = None

        for raw_line in sdp.splitlines():
            line = raw_line.strip()

            if not line:
                continue

            # ----------------------------------------------------------
            # Media section
            # ----------------------------------------------------------

            if line.startswith("m="):
                media = line[2:].split(" ", 1)[0].lower()

                if media == "video":
                    current_media = "video"
                    result.has_video = True

                elif media == "audio":
                    current_media = "audio"
                    result.has_audio = True

                else:
                    current_media = media

                continue

            # ----------------------------------------------------------
            # Codec
            # ----------------------------------------------------------

            if not line.startswith("a=rtpmap:"):
                continue

            codec_match = re.match(
                r"a=rtpmap:\d+\s+([A-Za-z0-9_-]+)",
                line,
                re.IGNORECASE,
            )

            if not codec_match:
                continue

            codec = codec_match.group(1).upper()

            if current_media == "video":
                if codec not in result.video_codecs:
                    result.video_codecs.append(codec)

            elif current_media == "audio":
                if codec not in result.audio_codecs:
                    result.audio_codecs.append(codec)
