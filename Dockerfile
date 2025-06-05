FROM ubuntu:22.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies including X11 libraries and other requirements
RUN apt-get update && apt-get install -y \
    wget \
    xz-utils \
    # Core Blender dependencies
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
    # Additional X11 libraries
    libsm6 \
    libice6 \
    libxext6 \
    libxfixes3 \
    libxcursor1 \
    libxcomposite1 \
    libxdamage1 \
    libx11-6 \
    libxau6 \
    libxdmcp6 \
    # Graphics and OpenGL
    libdrm2 \
    libxcb1 \
    libxcb-dri2-0 \
    libxcb-dri3-0 \
    libxcb-present0 \
    libxcb-sync1 \
    libxshmfence1 \
    libxxf86vm1 \
    # Audio libraries
    libasound2-dev \
    libpulse0 \
    # Python and utilities
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install Blender
WORKDIR /opt
RUN wget -q https://download.blender.org/release/Blender4.4/blender-4.4.3-linux-x64.tar.xz \
    && tar -xf blender-4.4.3-linux-x64.tar.xz \
    && rm blender-4.4.3-linux-x64.tar.xz \
    && mv blender-4.4.3-linux-x64 blender \
    && chmod +x /opt/blender/blender

# Set up Blender environment
ENV PATH="/opt/blender:$PATH"
ENV BLENDER_USER_CONFIG="/home/blender/.config/blender"
ENV BLENDER_USER_SCRIPTS="/home/blender/.config/blender/4.4/scripts"

# Create blender user and setup home directory
RUN useradd -m -s /bin/bash blender \
    && mkdir -p /home/blender/.config/blender/4.4/scripts/addons \
    && chown -R blender:blender /home/blender

# Switch to blender user
USER blender
WORKDIR /home/blender

# Create addon directory
RUN mkdir -p $BLENDER_USER_SCRIPTS/addons/blendscan

# Copy BlendScan addon
COPY --chown=blender:blender . $BLENDER_USER_SCRIPTS/addons/blendscan/

# Create configuration to enable BlendScan addon
RUN mkdir -p $BLENDER_USER_CONFIG/4.4/config \
    && echo "import bpy; bpy.utils.enable_addon('blendscan')" > $BLENDER_USER_CONFIG/4.4/config/startup.py

# Create startup script with better error handling
RUN echo '#!/bin/bash\n\
    set -e\n\
    \n\
    echo "=== BlendScan Security Analysis Tool ==="\n\
    echo "Comprehensive security analysis for Blender files"\n\
    echo ""\n\
    echo "Features:"\n\
    echo "  ✓ Real-time script analysis"\n\
    echo "  ✓ Auto-protection system"\n\
    echo "  ✓ Malware detection"\n\
    echo "  ✓ Secure script execution"\n\
    echo "  ✓ Base64/Hex decoding detection"\n\
    echo "  ✓ Network activity monitoring"\n\
    echo ""\n\
    echo "Usage Examples:"\n\
    echo "  # Interactive security scanning:"\n\
    echo "  docker run -it --rm -v /path/to/files:/data blendscan"\n\
    echo ""\n\
    echo "  # Scan specific file:"\n\
    echo "  docker run --rm -v /path/to/files:/data blendscan blender --background /data/file.blend"\n\
    echo ""\n\
    echo "  # GUI mode (Linux with X11):"\n\
    echo "  docker run -it --rm -v /path/to/files:/data \\\"\n\
    echo "    -v /tmp/.X11-unix:/tmp/.X11-unix:rw \\\"\n\
    echo "    -e DISPLAY=\$DISPLAY blendscan blender"\n\
    echo ""\n\
    \n\
    # Test if Blender can run\n\
    if ! /opt/blender/blender --version >/dev/null 2>&1; then\n\
    echo "ERROR: Blender installation test failed"\n\
    echo "This might be due to missing libraries or GPU drivers"\n\
    echo "Trying to run anyway..."\n\
    fi\n\
    \n\
    if [ "$#" -eq 0 ]; then\n\
    echo "Starting Blender in background mode for security scanning..."\n\
    echo "Loading BlendScan addon..."\n\
    \n\
    # Try to run Blender and load BlendScan\n\
    /opt/blender/blender --background --python-expr "\
    import bpy\n\
    import sys\n\
    import os\n\
    \n\
    try:\n\
    # Enable BlendScan addon\n\
    bpy.utils.enable_addon('\''blendscan'\'')\n\
    print('\''✓ BlendScan addon loaded successfully'\'')\n\
    \n\
    # Test security analyzer\n\
    from blendscan.analyzer import BlenderSecurityAnalyzer\n\
    analyzer = BlenderSecurityAnalyzer()\n\
    print('\''✓ Security analyzer initialized'\'')\n\
    print(f'\''✓ {len(analyzer.security_rules)} security rules loaded'\'')\n\
    \n\
    # Show auto-run status\n\
    auto_run = bpy.context.preferences.filepaths.use_scripts_auto_execute\n\
    print(f'\''✓ Auto-run scripts: {\"ENABLED (RISK!)\" if auto_run else \"DISABLED (SAFE)\"}'\'')\n\
    \n\
    print('\''\nBlendScan is ready for security analysis!'\'')\n\
    print('\''To scan files, mount them to /data and specify the path.'\'')\n\
    \n\
    except Exception as e:\n\
    print(f'\''✗ Error loading BlendScan: {e}'\'')\n\
    sys.exit(1)\
    " --enable-autoexec || {\n\
    echo "ERROR: Failed to start Blender with BlendScan"\n\
    echo "This might be due to graphics driver issues in the container"\n\
    echo "Try running with: --env LIBGL_ALWAYS_SOFTWARE=1"\n\
    exit 1\n\
    }\n\
    else\n\
    echo "Executing: blender $@"\n\
    exec /opt/blender/blender "$@"\n\
    fi' > /home/blender/start-blendscan.sh \
    && chmod +x /home/blender/start-blendscan.sh

# Set working directory for file operations
WORKDIR /data

# Expose volume for .blend files
VOLUME ["/data"]

# Default command
ENTRYPOINT ["/home/blender/start-blendscan.sh"]
CMD []
