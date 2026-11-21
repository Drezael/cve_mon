FROM python:3.12.16-alpine3.24@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
COPY apks/ /build/apks/
COPY apks.sha256 /build/apks.sha256
RUN cd /build/apks && sha256sum -c /build/apks.sha256 \
 && apk add --no-cache --no-network /build/apks/*.apk && rm -rf /build/apks /build/apks.sha256
ARG APPLICATION_UID=1000
ARG APPLICATION_GID=1000
RUN addgroup -g "$APPLICATION_GID" cve \
 && adduser -D -u "$APPLICATION_UID" -G cve -h /tmp/cve-home cve
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY runtime.txt /build/runtime.txt
COPY wheels/ /build/wheels/
COPY wheels.sha256 /build/wheels.sha256
RUN cd /build/wheels && sha256sum -c /build/wheels.sha256 \
 && python -m pip install --no-index --find-links=/build/wheels --require-hashes -r /build/runtime.txt \
 && python -m pip install --no-index --no-deps /build/wheels/cve_*.whl \
 && python -m pip check && rm -rf /build
USER 65532:65532
ENTRYPOINT ["python", "-m", "cve_common.application"]
