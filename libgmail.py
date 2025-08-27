import imaplib
import email
import os
import asyncio
from email.header import decode_header
from libcommon import extract_report, parse_and_store
from db import AsyncSessionLocal
from dotenv import load_dotenv

load_dotenv()
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
EMAIL_ACCOUNT = os.getenv("EMAIL_ID")
APP_PASSWORD = os.getenv("APP_PASS")

UPLOAD_DIR = "uploads"


async def process_file(file_path: str):
    async with AsyncSessionLocal() as db:
        await parse_and_store(file_path, db)


def connect_to_gmail():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
    return mail


async def fetch_dmarc_reports():
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)

    mail = connect_to_gmail()
    mail.select("inbox")

    # Search for messages with attachments & DMARC subject
    status, messages = mail.search(None, '(SUBJECT "Report Domain" UNSEEN)')  # UNSEEN

    if status != "OK":
        return {"status": "no new messages"}
    processed_files = []
    for num in messages[0].split():
        status, msg_data = mail.fetch(num, "(RFC822)")
        if status != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])

        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    filename = decode_header(filename)[0][0]
                    if isinstance(filename, bytes):
                        filename = filename.decode()

                    file_path = os.path.join(UPLOAD_DIR, filename)
                    with open(file_path, "wb") as f:
                        f.write(part.get_payload(decode=True))
                    processed_files.append(file_path)

                    extracted_files = extract_report(file_path, "extracted")
                    print(f"Report {filename} extracted to Extracted Dir")
                    for xml_file_path in extracted_files:
                        await process_file(xml_file_path)

        # Mark message as seen
        mail.store(num, "+FLAGS", "\\Seen")

    mail.logout()
    return {"status": "done", "processed": processed_files}
