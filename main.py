import shutil
import os
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_db
from models import Report, Record
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from pathlib import Path
from libgmail import fetch_dmarc_reports
import libcommon as util

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

UPLOADS_FOLDER = "uploads"
os.makedirs(UPLOADS_FOLDER, exist_ok=True)

# Application Frontend routes


@app.get("/upload_page", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(
        "upload.html", {"request": request, "message": "", "files": []}
    )


@app.post("/upload", response_class=HTMLResponse)
async def upload_file(
    request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)
):
    if not str(file.filename).endswith((".zip", ".gz", ".tar.gz")):
        return templates.TemplateResponse(
            "upload.html", {"request": request, "message": "only .zip file is allowed"}
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    upload_dir = Path(os.path.join(UPLOADS_FOLDER, timestamp))
    os.makedirs(upload_dir, exist_ok=True)

    zip_path = os.path.join(upload_dir, str(file.filename))

    file_path = os.path.join(UPLOADS_FOLDER, str(file.filename))
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    # extract Zip
    extracted_files = util.extract_report(str(zip_path), "extracted")

    # with zipfile.ZipFile(zip_path, "r") as zip_ref:
    #     for name in zip_ref.namelist():
    #         if name.endswith(".xml"):
    #             zip_ref.extract(name, upload_dir)
    #             extracted_files.append(os.path.join(upload_dir, name))
    # parse each xml file and insert into DB
    for xml_file in extracted_files:
        await util.parse_and_store(xml_file, db)
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "message": f"Uploaded {file.filename} successfully!",
            "files": extracted_files,
        },
    )


@app.get("/", response_class=HTMLResponse)
async def list_reports(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).order_by(Report.date_start.desc()))
    reports = result.scalars().all()
    return templates.TemplateResponse(
        "reports.html", {"request": request, "reports": reports}
    )


@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_details(
    report_id: int, request: Request, db: AsyncSession = Depends(get_db)
):

    stmt = (
        select(Report)
        .options(
            selectinload(Report.records).selectinload(
                Record.auth_results
            )  # ✅ Nested load
        )
        .where(Report.id == report_id)
    )
    result = await db.execute(stmt)

    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return templates.TemplateResponse(
        "report_details.html", {"request": request, "report": report}
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# Application API Routes
@app.get("/api/dashboard", response_class=JSONResponse)
async def dashboard_data(db: AsyncSession = Depends(get_db)):
    total_reports = await db.scalar(select(func.count(Report.id)))
    total_messages = await db.scalar(select(func.coalesce(func.sum(Record.count), 0)))

    disposition_result = await db.execute(
        select(Record.disposition, func.sum(Record.count)).group_by(Record.disposition)
    )

    disposition_counts = {row[0]: row[1] for row in disposition_result}

    spf_result = await db.execute(
        select(Record.spf_result, func.sum(Record.count)).group_by(Record.spf_result)
    )

    spf_counts = {row[0]: row[1] for row in spf_result}

    dkim_result = await db.execute(
        select(Record.dkim_result, func.sum(Record.count)).group_by(Record.dkim_result)
    )

    dkim_counts = {row[0]: row[1] for row in dkim_result}

    top_ips_query = await db.execute(
        select(Record.source_ip, func.sum(Record.count))
        .group_by(Record.source_ip)
        .order_by(func.sum(Record.count).desc())
        .limit(5),
    )

    top_ips = [{"ip": row[0], "count": row[1]} for row in top_ips_query]

    return {
        "total_reports": total_reports or 0,
        "total_messages": total_messages or 0,
        "disposition_counts": disposition_counts,
        "spf_results": spf_counts,
        "dkim_results": dkim_counts,
        "top_ips": top_ips,
    }


@app.post("/sync-reports")
async def sync_reports():
    result = await fetch_dmarc_reports()
    return result
