from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import shutil
import os
import zipfile
from datetime import datetime

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

UPLOADS_FOLDER = "uploads"
os.makedirs(UPLOADS_FOLDER, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "upload.html", {"request": request, "message": "", "files": []}
    )


@app.post("/upload", response_class=HTMLResponse)
async def upload_file(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        return templates.TemplateResponse(
            "upload.html", {"request": request, "message": "only .zip file is allowed"}
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    upload_dir = os.path.join(UPLOADS_FOLDER, timestamp)
    os.makedirs(upload_dir, exist_ok=True)

    zip_path = os.path.join(upload_dir, file.filename)

    file_path = os.path.join(UPLOADS_FOLDER, file.filename)
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    extracted_files = []

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for name in zip_ref.namelist():
            if name.endswith(".xml"):
                zip_ref.extract(name, upload_dir)
                extracted_files.append(name)

    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "message": f"Uploaed {file.filename} successfully!",
            "files": extracted_files,
        },
    )
