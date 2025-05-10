FROM python:3.9-slim
RUN apt-get update && apt-get install -y cron

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "0 * * * * root /usr/local/bin/python /app/clear_sessions.py" > /etc/cron.d/clear_sessions

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]