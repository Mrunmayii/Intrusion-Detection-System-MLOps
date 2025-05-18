# Use an official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . .

# Expose port (same as used in your app)
EXPOSE 5004

# Run the app
CMD ["uvicorn", "simulate_api:app", "--host", "0.0.0.0", "--port", "5004"]
