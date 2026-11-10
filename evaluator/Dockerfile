# syntax=docker/dockerfile:1.7
FROM python:3.12.7-slim@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
WORKDIR /app
COPY requirements.txt .
# Optional corporate/proxy CA for pip during build: compose passes secret `build_ca` (BUILD_CA_FILE in .env).
RUN --mount=type=secret,id=build_ca sh -c 'if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; pip install --no-cache-dir -r requirements.txt'
COPY app ./app
RUN mkdir -p /data
ENV EVAL_DB_PATH=/data/evaluator.db
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"]
