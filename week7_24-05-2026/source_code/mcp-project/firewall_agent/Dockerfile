FROM python:3.11-slim
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY agent.py .
CMD ["python", "-u", "agent.py"]
