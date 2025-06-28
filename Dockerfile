# Use Alpine Linux with Python for smaller image size
FROM python:3.11-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for cryptography
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    sqlite \
    && pip install --upgrade pip

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory for persistent storage
RUN mkdir -p /app/data

# Set environment variable for database path
ENV NOTES_DB_PATH=/app/data/notes.db

# Expose port 5000
EXPOSE 5000

# Create a non-root user for security
RUN adduser -D -u 1000 notesuser && \
    chown -R notesuser:notesuser /app
USER notesuser

# Default command to run the web server
CMD ["python", "notes.py", "server", "--host", "0.0.0.0", "--port", "5000"]
