FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && playwright install --with-deps chromium \
 && chmod -R a+rx /ms-playwright

COPY hunter/ hunter/
COPY tests/ tests/
COPY urls.txt .

# Run as an unprivileged user; the only writable mount should be /app/output.
RUN useradd -m -u 10001 hunter && mkdir -p /app/output && chown hunter /app/output
USER hunter

ENTRYPOINT ["python", "-m", "hunter.main"]
CMD ["--urls", "urls.txt", "--out", "output"]
