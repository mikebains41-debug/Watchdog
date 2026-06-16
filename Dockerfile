FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN mkdir -p watchdog_data
EXPOSE 8080
CMD ["python3", "watchdog.py", "--hz", "100", "--api", "--severity", "WARNING"]
