FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy the requirements files
COPY requirements.txt requirements-dev.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY docs/ ./docs/

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "src/main.py"]