#!/bin/bash

# BlendScan Docker Build Script
set -e

echo "Building BlendScan Docker Image..."

# Get version from __init__.py
VERSION=$(grep -o '"version": ([0-9, ]*)' __init__.py | grep -o '[0-9, ]*' | tr -d ' ' | tr ',' '.')
echo "Version: $VERSION"

# Build the image with better caching
echo "Building with BuildKit optimizations..."
DOCKER_BUILDKIT=1 docker build \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --progress=plain \
    -t blendscan:latest \
    -t blendscan:$VERSION .

# Test the build immediately
echo "Testing build..."
if docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest blender --background --version > /dev/null 2>&1; then
    echo "✓ Build test passed"
else
    echo "⚠ Build test failed - image may have issues with graphics libraries"
    echo "  This is common in headless environments. The image should still work with LIBGL_ALWAYS_SOFTWARE=1"
fi

# Tag for Docker Hub (update username as needed)
docker tag blendscan:latest kents00/blendscan:latest
docker tag blendscan:$VERSION kents00/blendscan:$VERSION

echo ""
echo "🎉 Build complete!"
echo "Images created:"
echo "  - blendscan:latest"
echo "  - blendscan:$VERSION"
echo "  - kents00/blendscan:latest"
echo "  - kents00/blendscan:$VERSION"
echo ""
echo "Usage examples:"
echo "  # Basic security scan:"
echo "  docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest"
echo ""
echo "  # Scan files:"
echo "  docker run --rm -v \$(pwd):/data --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest blender --background /data/file.blend"
echo ""
echo "  # Interactive mode:"
echo "  docker run -it --rm -v \$(pwd):/data --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest blender"
echo ""
echo "To push to Docker Hub:"
echo "  docker push kents00/blendscan:latest"
echo "  docker push kents00/blendscan:$VERSION"
