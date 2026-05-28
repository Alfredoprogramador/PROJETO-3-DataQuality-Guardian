from fastapi import FastAPI

app = FastAPI(title="DataQuality Guardian API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
