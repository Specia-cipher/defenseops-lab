<<<<<<< HEAD
FROM python:3.9-alpine
WORKDIR /app
COPY security_auditor_tool.py .
ENTRYPOINT ["python", "security_auditor_tool.py"]
=======
# DefenseOps Lab Dockerfile
FROM python:3.11-slim

# Metadata
LABEL maintainer="Sanni Idris"
LABEL description="DefenseOps Lab - Modular DevSecOps Toolkit"

# Set working directory
WORKDIR /opt/defenseops-lab

# Copy project files
COPY . /opt/defenseops-lab

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose default command
ENTRYPOINT ["python3"]
CMD ["log_analyzer_tool.py", "--help"]
>>>>>>> 65f7c86 (save local changes before rebase)
