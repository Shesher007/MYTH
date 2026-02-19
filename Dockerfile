# MYTH Desktop — OCI/Container Image (Feature 16/Modern Atomic support)
# Version: 1.1.6
# Author:  Shesher Hasan
# Build: docker build -t myth-desktop .
# Run (X11): docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix myth-desktop

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    libwebkit2gtk-4.1-0 \
    libssl3 \
    python3 \
    python3-pip \
    libgtk-3-0 \
    libappindicator3-1 \
    libcanberra-gtk-module \
    libcanberra-gtk3-module \
    dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

# Add application binary and resources
# In CI, we copy the release binary
COPY ui/src-tauri/target/release/myth /usr/bin/myth
RUN chmod +x /usr/bin/myth

# Default command
CMD ["/usr/bin/myth"]
