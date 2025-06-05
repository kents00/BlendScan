#!/bin/bash

# BlendScan Docker Test Script
set -e

echo "Testing BlendScan Docker Image..."

# Test 1: Check if Blender can run with software rendering
echo "1. Testing Blender installation with fallback rendering..."
docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest \
    blender --background --version || {
    echo "WARN: Blender failed with normal setup, trying alternative approach..."

    # Try with different approach
    docker run --rm blendscan:latest \
        /opt/blender/blender --background --factory-startup --python-expr "import bpy; print('Blender works'); quit()" || {
        echo "ERROR: Blender cannot run in this environment"
        echo "This may be due to missing graphics drivers or libraries"
        exit 1
    }
}

echo "2. Testing BlendScan addon loading..."
docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest \
    blender --background --factory-startup --python-expr "
import bpy
import sys
import os

# Add addon path
addon_path = '/home/blender/.config/blender/4.4/scripts/addons'
if addon_path not in sys.path:
    sys.path.append(addon_path)

try:
    # Try to enable the addon
    result = bpy.utils.enable_addon('blendscan')
    if result is None:
        print('BlendScan addon loaded successfully!')
    else:
        print(f'Addon enable result: {result}')

    # Test analyzer import
    from blendscan.analyzer import BlenderSecurityAnalyzer
    analyzer = BlenderSecurityAnalyzer()
    print(f'Security analyzer loaded with {len(analyzer.security_rules)} rules')

except ImportError as e:
    print(f'Import error: {e}')
    print('Available modules in addon path:')
    for item in os.listdir(addon_path):
        print(f'  - {item}')
    sys.exit(1)
except Exception as e:
    print(f'Error loading BlendScan: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
" || {
    echo "ERROR: BlendScan addon failed to load"
    echo "Checking addon installation..."
    docker run --rm blendscan:latest ls -la /home/blender/.config/blender/4.4/scripts/addons/blendscan/
    exit 1
}

echo "3. Testing security analysis functionality..."
docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest \
    blender --background --factory-startup --python-expr "
import bpy
import sys

# Add addon path
addon_path = '/home/blender/.config/blender/4.4/scripts/addons'
if addon_path not in sys.path:
    sys.path.append(addon_path)

try:
    bpy.utils.enable_addon('blendscan')
    from blendscan.analyzer import BlenderSecurityAnalyzer

    analyzer = BlenderSecurityAnalyzer()

    # Test malicious script detection
    malicious_code = '''
import os
import base64
decoded = base64.b64decode(\"dGVzdA==\")
os.system(\"echo test\")
'''

    result = analyzer.analyze_script(malicious_code, 'test_script.py')

    print(f'Security analysis result:')
    print(f'  Risk Level: {result[\"risk_level\"]}')
    print(f'  Issues Found: {len(result[\"issues\"])}')

    # Check for expected detections
    critical_issues = [issue for issue in result['issues'] if issue['severity'] == 'CRITICAL']
    if len(critical_issues) >= 2:  # Should detect base64 and os.system
        print('✓ Security analyzer working correctly!')
    else:
        print('✗ Security analyzer not detecting threats properly')
        for issue in result['issues']:
            print(f'  - {issue[\"type\"]}: {issue[\"severity\"]}')
        sys.exit(1)

except Exception as e:
    print(f'Error testing security analysis: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

echo "4. Testing file security scan..."
# Create a test file with embedded malicious content
docker run --rm -v "$(pwd)/test-files":/test-data --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest \
    bash -c "
    mkdir -p /test-data
    echo 'import os; os.system(\"rm -rf /\")' > /test-data/malicious_script.py
    blender --background --factory-startup --python-expr \"
import bpy
import sys
addon_path = '/home/blender/.config/blender/4.4/scripts/addons'
if addon_path not in sys.path:
    sys.path.append(addon_path)

bpy.utils.enable_addon('blendscan')
from blendscan.analyzer import BlenderSecurityAnalyzer

# Create a text block with malicious content
text = bpy.data.texts.new('malicious.py')
text.write('import os; os.system(\\\"rm -rf /\\\"); import base64; base64.b64decode(\\\"test\\\")')

analyzer = BlenderSecurityAnalyzer()
results = analyzer.analyze_blend_file_security(bpy.context)

print(f'Blend file analysis:')
print(f'  Overall Risk: {results[\\\"overall_risk\\\"]}')
print(f'  Scripts Found: {len(results[\\\"embedded_scripts\\\"])}')

if results['overall_risk'] in ['HIGH', 'CRITICAL']:
    print('✓ Malicious content detected correctly!')
else:
    print('✗ Failed to detect malicious content')
    sys.exit(1)
\"
    rm -f /test-data/malicious_script.py
"

echo ""
echo "🎉 All tests passed! BlendScan Docker image is working correctly."
echo ""
echo "Available commands:"
echo "  # Basic security scan:"
echo "  docker run --rm --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest"
echo ""
echo "  # Scan specific files:"
echo "  docker run --rm -v /path/to/files:/data --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest blender --background /data/file.blend"
echo ""
echo "  # Interactive mode:"
echo "  docker run -it --rm -v /path/to/files:/data --env LIBGL_ALWAYS_SOFTWARE=1 blendscan:latest blender"
