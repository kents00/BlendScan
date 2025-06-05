#!/bin/bash

# BlendScan Docker Build Script
set -e

echo "Building BlendScan Docker Image..."

# Get version from __init__.py
VERSION=$(grep -o '"version": ([0-9, ]*)' __init__.py | grep -o '[0-9, ]*' | tr -d ' ' | tr ',' '.')
echo "Version: $VERSION"

# Build the image
docker build -t blendscan:latest .
docker build -t blendscan:$VERSION .

# Tag for Docker Hub (update username as needed)
docker tag blendscan:latest kents00/blendscan:latest
docker tag blendscan:$VERSION kents00/blendscan:$VERSION

echo "Build complete!"
echo "Images created:"
echo "  - blendscan:latest"
echo "  - blendscan:$VERSION"
echo "  - kents00/blendscan:latest"
echo "  - kents00/blendscan:$VERSION"
echo ""
echo "To push to Docker Hub:"
echo "  docker push kents00/blendscan:latest"
echo "  docker push kents00/blendscan:$VERSION"
