FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY exporter.py .

# Shared volume mount point
RUN mkdir -p /shared

EXPOSE 9101

CMD ["python", "-u", "exporter.py"]
