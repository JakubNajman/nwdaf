FROM python:3.11-slim

WORKDIR /app

COPY req.txt .
RUN pip install --no-cache-dir -r req.txt

COPY . .

EXPOSE 8080

CMD ["gunicorn", \
     "--worker-class", "gevent", \
     "--workers", "1", \
     "--bind", "0.0.0.0:8080", \
     "--timeout", "120", \
     "--log-level", "info", \
     "main:app"]