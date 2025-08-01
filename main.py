from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import shutil
import os
import zipfile
from datetime import datetime
import xml.etree.ElementTree as ET
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_db
from models import Report, Record, AuthResult
from sqlalchemy import select
from sqlalchemy.orm import selectinload

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

UPLOADS_FOLDER = "uploads"
os.makedirs(UPLOADS_FOLDER, exist_ok=True)


#  Utility functions
def normalize_ts(ts: str) -> int:
    val = int(ts)
    if val > 1e12:  # Likely milliseconds
        val = val // 1000
    return val


async def parse_and_store(xml_path: str, db: AsyncSession):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Handle namespases
    if "}" in root.tag:
        ns_uri = root.tag.split("}")[0].strip("{")
        ns = {"ns": ns_uri}
        prefix = "ns"
    else:
        ns = {}
        prefix = None

    def xp(path: str) -> str:
        if prefix:
            return path.replace("//", f"//{prefix}:").replace("./", f"./{prefix}:")
        return path

    org_name = root.findtext(".//report_metadata/org_name", namespaces=ns)
    email = root.findtext(".//report_metadata/email", namespaces=ns)
    report_id = root.findtext(".//report_metadata/report_id", namespaces=ns)
    date_start = root.findtext(".//report_metadata/date_range/begin", namespaces=ns)
    date_end = root.findtext(".//report_metadata/date_range/end", namespaces=ns)

    # convent timestamps to datetime
    date_start = datetime.fromtimestamp(normalize_ts(int(date_start)))
    date_end = datetime.fromtimestamp(normalize_ts(int(date_end)))

    # extract policy_published
    policy_domain = root.findtext(".//policy_published/domain", namespaces=ns)
    policy_adkim = root.findtext(".//policy_published/adkim", namespaces=ns)
    policy_aspf = root.findtext(".//policy_published/aspf", namespaces=ns)
    policy_p = root.findtext(".//policy_published/p", namespaces=ns)

    # Insert into report
    report = Report(
        org_name=org_name,
        email=email,
        report_id=report_id,
        date_start=date_start,
        date_end=date_end,
        policy_domain=policy_domain,
        policy_adkim=policy_adkim,
        policy_aspf=policy_aspf,
        policy_p=policy_p,
        raw_file_path=xml_path,
    )
    db.add(report)
    await db.flush()

    for record_el in root.findall(".//record", namespaces=ns):
        source_ip = record_el.findtext(".//row/source_ip", namespaces=ns)
        count = record_el.findtext(".//row/count", namespaces=ns)
        disposition = record_el.findtext(
            ".//row/policy_evaluated/disposition", namespaces=ns
        )
        dkim_result = record_el.findtext(".//row/policy_evaluated/dkim", namespaces=ns)
        spf_result = record_el.findtext(".//row/policy_evaluated/spf", namespaces=ns)
        header_from = record_el.findtext(".//identifiers/header_from", namespaces=ns)

        record = Record(
            report_id=report.id,
            source_ip=source_ip,
            count=int(count),
            disposition=disposition,
            dkim_result=dkim_result,
            spf_result=spf_result,
            header_from=header_from,
        )
        db.add(record)
        await db.flush()

        auth_results_el = record_el.find(xp("./auth_results"), namespaces=ns)
        if auth_results_el is not None:
            # DKIM entries
            for dkim_el in auth_results_el.findall(xp("./dkim"), namespaces=ns):
                domain = dkim_el.findtext(xp("./domain"), namespaces=ns)
                result = dkim_el.findtext(xp("./result"), namespaces=ns)
                selector = dkim_el.findtext(xp("./selector"), namespaces=ns)
                auth_result = AuthResult(
                    record_id=record.id,
                    auth_type="dkim",
                    domain=domain,
                    result=result,
                    selector=selector,
                )
                db.add(auth_result)

            # SPF entries
            for spf_el in auth_results_el.findall(xp("./spf"), namespaces=ns):
                domain = spf_el.findtext(xp("./domain"), namespaces=ns)
                result = spf_el.findtext(xp("./result"), namespaces=ns)
                auth_result = AuthResult(
                    record_id=record.id, auth_type="spf", domain=domain, result=result
                )
                db.add(auth_result)

    await db.commit()


# Application routes


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "upload.html", {"request": request, "message": "", "files": []}
    )


@app.post("/upload", response_class=HTMLResponse)
async def upload_file(
    request: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)
):
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
    # extract Zip
    extracted_files = []

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for name in zip_ref.namelist():
            if name.endswith(".xml"):
                zip_ref.extract(name, upload_dir)
                extracted_files.append(os.path.join(upload_dir, name))
    # parse each xml file and insert into DB
    for xml_file in extracted_files:
        await parse_and_store(xml_file, db)
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "message": f"Uploaded {file.filename} successfully!",
            "files": extracted_files,
        },
    )


@app.get("/reports", response_class=HTMLResponse)
async def list_reports(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).order_by(Report.date_start.desc()))
    reports = result.scalars().all()
    print(reports)
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
