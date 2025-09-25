FROM python:3.11-slim AS base

ENV APP_USER=appuser
RUN addgroup --system ${APP_USER} && adduser --system --ingroup ${APP_USER} ${APP_USER}

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN chown -R ${APP_USER}:${APP_USER} /app

USER ${APP_USER}

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080 2222 2121

VOLUME ["/app/logs"]

CMD ["python", "-m", "honeypot.main"]
