# ================================================================== #
#  Ryu ZTNA Controller — Docker Image                                  #
#  Python 3.8 (Ryu compatibility requirement)                          #
# ================================================================== #

FROM python:3.8-slim

LABEL maintainer="ZTA-Project"
LABEL description="Ryu OpenFlow 1.3 controller for Zero Trust network enforcement"

# Install OS dependencies for Ryu
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Ryu and dependencies
# Pinned versions for Python 3.8 compatibility
RUN pip install --no-cache-dir \
    ryu==4.34 \
    eventlet==0.30.2 \
    webob==1.8.7 \
    oslo.config \
    msgpack==1.0.5

# Copy only the SDN controller app
COPY ryu_ztna_app.py .

# OpenFlow port (switch → controller)
EXPOSE 6653

# Ryu REST API port
EXPOSE 8085

# Health check against Ryu REST API
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8085/ztna/health || exit 1

# Launch Ryu with WSGI REST enabled on port 8085
CMD ["ryu-manager", \
     "--wsapi-port", "8085", \
     "--ofp-tcp-listen-port", "6653", \
     "--verbose", \
     "ryu_ztna_app.py"]
