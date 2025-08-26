# running the project

```bash
docker buildx build -t dmarc-parser:v1.0 .
docker run -p 5000:5000 --restart always -d -v ./data:/app/data -v ./uploads:/app/uploads -v ./extracted:/app/extracted  dmarc-parser:v1.0
```
