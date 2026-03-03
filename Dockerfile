# Use official Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Suppress Tor notices
ENV TOR_LOG="err"

# Install Tor and necessary tools
RUN apt-get update && \
    apt-get install -y tor && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Expose Tor SOCKS port (optional, if you want to connect from outside)
EXPOSE 9050

# Default command to run: start Tor in background, then run your script
CMD tor & python main.py Book1.csv
