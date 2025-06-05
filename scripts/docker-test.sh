#!/bin/bash

# BlendScan Docker Test Script
set -e

echo "Testing BlendScan Docker Image..."

# Test basic functionality
echo "1. Testing Blender installation..."
docker run --rm blendscan:latest blender --version

echo "2. Testing BlendScan addon loading..."
docker run --rm blendscan:latest blender --background --python-expr "
import bpy
try:
    import bpy.utils
    # Try to enable the addon
    bpy.utils.enable_addon('blendscan')
    print('BlendScan addon loaded successfully!')
except Exception as e:
    print(f'Error loading BlendScan: {e}')
    exit(1)
"

echo "3. Testing security analysis..."
docker run --rm blendscan:latest blender --background --python-expr "
import bpy
from blendscan.analyzer import BlenderSecurityAnalyzer
analyzer = BlenderSecurityAnalyzer()
print('Security analyzer initialized successfully!')
"

echo "All tests passed! ✅"
