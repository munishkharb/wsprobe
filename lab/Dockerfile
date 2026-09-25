# Runs the two shipped synthetic targets (the vulnerable fixture and the clean
# control) so the lab stands them up alongside a third-party target. Nothing
# here is wsprobe itself — these are the practice servers wsprobe is pointed at.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "websockets>=13.0"
COPY tests/fixture.py tests/control.py tests/__init__.py ./targets/
# targets/ is importable as a package
RUN touch targets/__init__.py 2>/dev/null || true
EXPOSE 8799 8798
