FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y tshark && \
    pip install --no-cache-dir -r requirements.txt
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5001"]
