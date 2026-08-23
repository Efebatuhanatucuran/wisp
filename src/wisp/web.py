from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import cve, discovery, report, scanner
from .models import ScanResult

_STATIC_DIR = Path(__file__).parent / "static"
_EXAMPLES_DIR = Path(__file__).parent / "examples"
_EXAMPLES = {
    "risky": "risky-config.json",
    "safe": "safe-config.json",
}

_CVE_FEED_REFRESH_SECONDS = 6 * 3600


class FileUpload(BaseModel):
    name: str
    content: str


class ScanRequest(BaseModel):
    paths: list[str] | None = None
    files: list[FileUpload] | None = None
    project_dir: str | None = None
    check_cve: bool = True


async def _cve_feed_refresher() -> None:
    while True:
        await asyncio.to_thread(cve.fetch_mcp_cve_feed_cached, force=True)
        await asyncio.sleep(_CVE_FEED_REFRESH_SECONDS)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    task = asyncio.create_task(_cve_feed_refresher())
    try:
        yield
    finally:
        task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(title="Wisp", lifespan=_lifespan)

    @app.get("/api/discover")
    def api_discover(project_dir: str | None = None) -> dict:
        base = Path(project_dir) if project_dir else None
        files = discovery.discover_config_files(base)
        return {"files": [str(p) for p in files]}

    @app.get("/api/examples/{name}")
    def api_example(name: str) -> dict:
        filename = _EXAMPLES.get(name)
        if not filename:
            raise HTTPException(status_code=404, detail=f"no such example: {name}")
        content = (_EXAMPLES_DIR / filename).read_text()
        return {"name": filename, "content": content}

    def _run_scan(req: ScanRequest) -> ScanResult:
        paths = [Path(p) for p in req.paths] if req.paths else None
        inline_files = [(f.name, f.content) for f in req.files] if req.files else None
        project_dir = Path(req.project_dir) if req.project_dir else None
        try:
            return scanner.scan(
                paths=paths, project_dir=project_dir, inline_files=inline_files, check_cve=req.check_cve,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/scan")
    def api_scan(req: ScanRequest) -> dict:
        return report.to_dict(_run_scan(req))

    @app.post("/api/scan/report.html")
    def api_scan_report_html(req: ScanRequest) -> HTMLResponse:
        html = report.to_html(_run_scan(req))
        return HTMLResponse(
            content=html,
            headers={"Content-Disposition": 'attachment; filename="wisp-report.html"'},
        )

    @app.get("/api/cve-feed")
    def api_cve_feed(refresh: bool = False) -> dict:
        items, fetched_at = cve.fetch_mcp_cve_feed_cached(force=refresh)
        return {
            "items": items,
            "fetched_at": datetime.fromtimestamp(fetched_at, tz=timezone.utc).isoformat(),
            "source": 'NVD keyword search: "Model Context Protocol"',
        }

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    return app
