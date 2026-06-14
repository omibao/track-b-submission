FROM python:3.12.8-slim-bookworm@sha256:8859bd6ca943079262c27e38b7119cdacede77c463139a15651dd340087a6cc9

RUN useradd -u 1000 -m -d /home/skillsec skillsec

RUN mkdir -p /data/skills /output && chown skillsec:skillsec /output

WORKDIR /app
COPY --chown=skillsec:skillsec engine/engine.py /app/engine.py

ENV PYTHONUNBUFFERED=1
USER 1000
ENTRYPOINT ["python", "/app/engine.py"]
