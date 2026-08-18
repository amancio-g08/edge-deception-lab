FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY honeypot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot/app ./honeypot/app
COPY honeypot/__init__.py ./honeypot/__init__.py

# The sensor writes only to /data and never needs to own its own code.
RUN useradd --system --uid 10001 --create-home sensor \
    && mkdir -p /data \
    && chown -R sensor:sensor /data
USER sensor

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/_edl/api/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "honeypot.app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "*"]
