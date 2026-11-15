FROM ghcr.io/gitleaks/gitleaks:v8.24.2 AS gitleaks

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
