from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from unknown_camera.network import NetworkScanOptions

from web.discovery import DiscoveryManager


BASE_DIR = Path(__file__).resolve().parent


app = FastAPI(
    title="UnknownCameraSDK",
)


app.mount(
    "/static",
    StaticFiles(
        directory=BASE_DIR / "web" / "static"
    ),
    name="static",
)


templates = Jinja2Templates(
    directory=BASE_DIR / "web" / "templates"
)


discovery = DiscoveryManager()


@app.get("/")
async def discovery_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="discovery.html",
        context={},
    )


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "UnknownCameraSDK-Web",
    }


@app.post("/api/discovery/scan")
async def start_discovery_scan():
    started = await discovery.start(
        NetworkScanOptions()
    )

    if not started:
        return {
            "ok": False,
            "running": True,
        }

    return {
        "ok": True,
        "running": True,
    }


@app.get("/api/discovery/events")
async def discovery_events():

    async def event_stream():
        while True:
            event = await discovery.next_event()

            yield (
                "data: "
                + json.dumps(
                    event,
                    ensure_ascii=False,
                )
                + "\n\n"
            )

            if event.get("type") in {
                "scan_finished",
                "scan_error",
                "scan_cancelled",
            }:
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
