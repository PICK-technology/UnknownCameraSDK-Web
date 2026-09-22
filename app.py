from fastapi import FastAPI

app = FastAPI(
    title="UnknownCameraSDK",
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "UnknownCameraSDK-Web",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
