# syntax=docker/dockerfile:1.7
FROM python:3.12.7-slim@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d
WORKDIR /app
# Optional corporate/proxy CA for pip during build: compose passes secret `build_ca` (BUILD_CA_FILE in .env).
RUN --mount=type=secret,id=build_ca sh -c 'if [ -s /run/secrets/build_ca ]; then export PIP_CERT=/run/secrets/build_ca; fi; pip install --no-cache-dir starlette==0.41.3 uvicorn==0.32.1'
COPY server.py .
EXPOSE 8080
CMD ["python", "server.py"]
