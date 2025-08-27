import zipfile, gzip, tarfile, shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from models import Report, Record, AuthResult

#  Utility functions


def extract_report(file_path: str, extract_to: str) -> list[str]:
    """
    Extract DMARC report file to extract_to folder.
    Supports .zip, .gz, .tar.gz
    Returns list of extracted XML file paths.
    """
    extracted_files = []
    path = Path(file_path)
    extract_dir = Path(extract_to)
    extract_dir.mkdir(parents=True, exist_ok=True)

    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "r") as z:
            z.extractall(extract_dir)
            extracted_files = [
                str(extract_dir / name)
                for name in z.namelist()
                if name.endswith(".xml")
            ]

    elif path.suffix == ".gz" and not path.name.endswith(".tar.gz"):
        # Single XML inside .gz
        out_file = extract_dir / path.stem  # remove .gz
        with gzip.open(path, "rb") as gz_in:
            with open(out_file, "wb") as out_f:
                shutil.copyfileobj(gz_in, out_f)
        if out_file.suffix == "":
            out_file = out_file.with_suffix(".xml")  # rename if missing extension
        extracted_files = [str(out_file)]

    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(extract_dir)
            extracted_files = [str(f) for f in extract_dir.rglob("*.xml")]

    else:
        raise ValueError(f"Unsupported file format: {path.suffixes}")

    return extracted_files


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
    date_start = datetime.fromtimestamp(int(date_start or 0))
    date_end = datetime.fromtimestamp(int(date_end or 0))

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
            count=int(count or 0),
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
