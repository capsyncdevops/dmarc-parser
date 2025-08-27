# running the project

```powershell
docker buildx build -t dmarc-parser:v1.1 .
docker run -p 5000:5000 --restart always -d |
    -v ./data:/app/data -v ./uploads:/app/uploads |
    -v ./extracted:/app/extracted |
    -e DB_URL="sqlite+aiosqlite:///.data/.db.sqlite3" |
    dmarc-parser:v1.1
```

```bash
docker buildx build -t dmarc-parser:v1.0 .
docker run -p 5000:5000 --restart always -d \
    -v ./data:/app/data -v ./uploads:/app/uploads \
    -v ./extracted:/app/extracted \
    -e DB_URL="sqlite+aiosqlite:///.data/db.sqlite3" \
    dmarc-parser:v1.0
```
