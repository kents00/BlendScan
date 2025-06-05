FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    xz-utils \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libxrandr2 \
    libxss1 \
    libgconf-2-4 \
    libasound2 \
    libatk1.0-0 \
    libgtk-3-0 \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Blender
WORKDIR /opt
RUN wget -q https://download.blender.org/release/Blender4.4/blender-4.4.3-linux-x64.tar.xz \
    && tar -xf blender-4.4.3-linux-x64.tar.xz \
    && rm blender-4.4.3-linux-x64.tar.xz \
    && mv blender-4.4.3-linux-x64 blender

# Set up Blender environment
ENV PATH="/opt/blender:$PATH"
ENV BLENDER_USER_CONFIG="/home/blender/.config/blender"
ENV BLENDER_USER_SCRIPTS="/home/blender/.config/blender/4.4/scripts"

# Create blender user
RUN useradd -m -s /bin/bash blender

# Create addon directories
USER blender
WORKDIR /home/blender
RUN mkdir -p $BLENDER_USER_SCRIPTS/addons/blendscan

# Copy BlendScan addon
COPY --chown=blender:blender . $BLENDER_USER_SCRIPTS/addons/blendscan/

# Create startup script
RUN echo '#!/bin/bash\n\
    echo "Starting Blender with BlendScan Security Addon"\n\
    echo "BlendScan provides comprehensive security analysis for .blend files"\n\
    echo "Features:"\n\
    echo "- Real-time script analysis"\n\
    echo "- Auto-protection system"\n\
    echo "- Malware detection"\n\
    echo "- Secure script execution"\n\
    echo ""\n\
    echo "Usage:"\n\
    echo "  docker run -it --rm -v /path/to/files:/data blendscan"\n\
    echo "  docker run -it --rm -v /path/to/files:/data blendscan blender /data/file.blend"\n\
    echo ""\n\
    if [ "$#" -eq 0 ]; then\n\
    echo "Starting Blender in background mode for security scanning..."\n\
    blender --background --python-expr "import bpy; print('\''BlendScan loaded successfully'\'')" --enable-autoexec\n\
    else\n\
    echo "Executing: blender $@"\n\
    blender "$@"\n\
    fi' > /home/blender/start-blendscan.sh \
    && chmod +x /home/blender/start-blendscan.sh

# Set working directory for file operations
WORKDIR /data

# Expose volume for .blend files
VOLUME ["/data"]

# Default command
ENTRYPOINT ["/home/blender/start-blendscan.sh"]
CMD ["--help"]
