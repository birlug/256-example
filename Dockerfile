FROM python:3.12-alpine
WORKDIR /app
COPY solution.py payload.b64 /app/
ENTRYPOINT ["python3", "/app/solution.py"]
