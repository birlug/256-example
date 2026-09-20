FROM python:3.12-alpine
WORKDIR /app
COPY solution /app/solution
ENTRYPOINT ["python3", "-m", "solution"]
