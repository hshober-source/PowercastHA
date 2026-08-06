FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ADDON_APP_DIR=/app \
    ADDON_DATA_DIR=/data

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends bluetooth bluez libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY addon_runtime.py /app/addon_runtime.py
COPY ha_bridge.py /app/ha_bridge.py
COPY ui/index.html /app/ui/index.html
COPY vendor/hub_ingester.py /app/vendor/hub_ingester.py
# Generated from the canonical repository source by
# scripts/sync_homeassistant_ble_hub.py. Do not hand-edit this directory.
COPY vendor/python_ble_hub /app/vendor/python_ble_hub

EXPOSE 8091

CMD ["python", "/app/addon_runtime.py"]
