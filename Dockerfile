FROM python:3.9-alpine
WORKDIR /app
COPY security_auditor_tool.py .
ENTRYPOINT ["python", "security_auditor_tool.py"]
