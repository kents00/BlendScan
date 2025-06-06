import bpy
import time
import re
import os
import ast
import hashlib
import base64
import binascii
from typing import List, Dict, Tuple, Set, Optional

class BlenderSecurityRule:
    def __init__(self, name: str, pattern: str, severity: str, description: str, category: str = "GENERAL"):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.severity = severity  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        self.description = description
        self.category = category

class BlenderSecurityAnalyzer:
    def __init__(self):
        self.security_rules = self._load_blender_security_rules()
        self.suspicious_imports = {
            'os', 'subprocess', 'base64', 'requests', 'urllib', 'socket',
            'pickle', 'marshal', 'eval', 'exec', 'compile', 'time.sleep',
            'webbrowser', 'ftplib', 'smtplib', 'telnetlib', 'poplib',
            'imaplib', 'nntplib', 'zipfile', 'tarfile', 'shutil', 'ctypes',
            'winreg', '_winreg', 'getpass', 'keyring', 'cryptography',
            'paramiko', 'psutil', 'win32api', 'win32con', 'win32security',
            'pycryptodome', 'Crypto', 'ssl', 'hashlib', 'hmac'
        }
        self.obfuscation_indicators = [
            'base64.b64decode', 'base64.decode', 'codecs.decode',
            'binascii.unhexlify', 'bytes.fromhex', 'chr(', 'ord(',
            'rot13', 'zlib.decompress', 'gzip.decompress', 'bz2.decompress',
            'lzma.decompress', 'codecs.escape_decode', 'eval(', 'exec(',
            'compile(', '__import__', 'getattr(', 'setattr(', 'hasattr(',
            'globals()', 'locals()', 'vars()', 'dir()'
        ]

    def _load_blender_security_rules(self) -> List[BlenderSecurityRule]:
        """Load security rules specific to Blender vulnerabilities"""
        rules = [
            # CRITICAL RISK PATTERNS

            # Base64 Obfuscation (Enhanced)
            BlenderSecurityRule(
                "Base64 Decoding",
                r"base64\.(?:b64decode|decode|decodebytes|standard_b64decode|urlsafe_b64decode)\s*\(",
                "CRITICAL",
                "Base64 decoding detected - strong indicator of malicious intent",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "Multiple Encoding Layers",
                r"(?:base64|binascii|codecs)\..*(?:base64|binascii|codecs)\.",
                "CRITICAL",
                "Multiple encoding layers detected - advanced obfuscation",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "Base64 String Pattern",
                r"['\"][A-Za-z0-9+/]{100,}={0,2}['\"]",
                "HIGH",
                "Large base64 encoded string - potential malicious payload",
                "OBFUSCATION"
            ),

            # System Command Execution (Enhanced)
            BlenderSecurityRule(
                "System Command Execution",
                r"(?:os\.system|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(",
                "CRITICAL",
                "System command execution - can run external programs",
                "SYSTEM"
            ),
            BlenderSecurityRule(
                "PowerShell Execution",
                r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|/bin/(?:sh|bash|zsh))",
                "CRITICAL",
                "Shell execution detected - major security risk",
                "SHELL"
            ),
            BlenderSecurityRule(
                "Command Injection Patterns",
                r"(?:&&|\|\||;|\$\(|\`)",
                "HIGH",
                "Command injection patterns detected",
                "SYSTEM"
            ),

            # Dynamic Code Execution (Enhanced)
            BlenderSecurityRule(
                "Dynamic Code Execution",
                r"(?:eval|exec|compile)\s*\(",
                "CRITICAL",
                "Dynamic code execution - can run arbitrary malicious code",
                "EXECUTION"
            ),
            BlenderSecurityRule(
                "Code Object Creation",
                r"(?:types\.CodeType|marshal\.loads|pickle\.loads)\s*\(",
                "CRITICAL",
                "Code object creation - potential code injection",
                "EXECUTION"
            ),

            # HIGH RISK PATTERNS

            # Network Activity (Enhanced)
            BlenderSecurityRule(
                "HTTP Requests",
                r"(?:requests\.(?:get|post|put|delete|head|options)|urllib\.(?:request|urlopen))",
                "HIGH",
                "HTTP requests detected - potential data exfiltration",
                "NETWORK"
            ),
            BlenderSecurityRule(
                "Socket Communication",
                r"socket\.(?:socket|connect|bind|listen|accept|send|recv)",
                "HIGH",
                "Socket communication - direct network access",
                "NETWORK"
            ),
            BlenderSecurityRule(
                "FTP/Email Protocols",
                r"(?:ftplib\.|smtplib\.|poplib\.|imaplib\.|telnetlib\.)",
                "HIGH",
                "Network protocol usage - potential data transmission",
                "NETWORK"
            ),
            BlenderSecurityRule(
                "URL Patterns",
                r"https?://[^\s'\"\)]+",
                "MEDIUM",
                "Hardcoded URLs detected - potential C&C communication",
                "NETWORK"
            ),

            # File System Manipulation (Enhanced)
            BlenderSecurityRule(
                "File Deletion",
                r"(?:os\.(?:remove|unlink|rmdir|removedirs)|shutil\.(?:rmtree|move))\s*\(",
                "HIGH",
                "File deletion operations - can destroy data",
                "FILESYSTEM"
            ),
            BlenderSecurityRule(
                "Directory Operations",
                r"(?:os\.(?:mkdir|makedirs|chdir|listdir|walk)|shutil\.(?:copytree|move))\s*\(",
                "MEDIUM",
                "Directory manipulation operations",
                "FILESYSTEM"
            ),
            BlenderSecurityRule(
                "Temporary File Operations",
                r"(?:tempfile\.|mktemp|mkstemp)",
                "MEDIUM",
                "Temporary file operations - potential staging area",
                "FILESYSTEM"
            ),

            # Credential Harvesting
            BlenderSecurityRule(
                "Password Collection",
                r"(?:getpass\.getpass|input\(['\"].*password.*['\"]|raw_input\(['\"].*password.*['\"])",
                "HIGH",
                "Password collection detected - credential harvesting",
                "CREDENTIALS"
            ),
            BlenderSecurityRule(
                "Keyring Access",
                r"(?:keyring\.|win32cred\.|secretstorage\.)",
                "HIGH",
                "System credential store access",
                "CREDENTIALS"
            ),
            BlenderSecurityRule(
                "Environment Variables",
                r"os\.environ\[.*(?:TOKEN|KEY|PASS|SECRET|AUTH)",
                "MEDIUM",
                "Accessing sensitive environment variables",
                "CREDENTIALS"
            ),

            # MEDIUM RISK PATTERNS

            # Large Encoded Strings (Enhanced)
            BlenderSecurityRule(
                "Large Hexadecimal String",
                r"['\"][0-9a-fA-F]{100,}['\"]",
                "MEDIUM",
                "Large hexadecimal string - possible encoded payload",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "Mixed Encoding Patterns",
                r"(?:\\x[0-9a-fA-F]{2}){20,}",
                "MEDIUM",
                "Hex escape sequences - potential obfuscated strings",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "Unicode Escape Sequences",
                r"(?:\\u[0-9a-fA-F]{4}){10,}",
                "MEDIUM",
                "Unicode escape sequences - potential obfuscation",
                "OBFUSCATION"
            ),

            # Time-based Evasion (Enhanced)
            BlenderSecurityRule(
                "Sleep Operations",
                r"time\.sleep\s*\(",
                "LOW",
                "Sleep operations - possible evasion technique",
                "EVASION"
            ),
            BlenderSecurityRule(
                "Timer Operations",
                r"(?:threading\.Timer|timer\.|schedule\.)",
                "MEDIUM",
                "Timer operations - potential delayed execution",
                "EVASION"
            ),

            # Registry Access
            BlenderSecurityRule(
                "Windows Registry Access",
                r"(?:winreg\.|_winreg\.|reg\s+(?:add|delete|query))",
                "HIGH",
                "Windows registry access - system modification",
                "REGISTRY"
            ),
            BlenderSecurityRule(
                "Registry Key Patterns",
                r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)",
                "MEDIUM",
                "Registry key references",
                "REGISTRY"
            ),

            # BLENDER-SPECIFIC THREATS (Enhanced)

            # Driver Expressions
            BlenderSecurityRule(
                "Driver Namespace Manipulation",
                r"bpy\.app\.driver_namespace",
                "HIGH",
                "Driver namespace manipulation - scripts can hide in drivers",
                "BLENDER"
            ),
            BlenderSecurityRule(
                "Driver Expression Injection",
                r"driver\.expression\s*=",
                "MEDIUM",
                "Dynamic driver expression modification",
                "BLENDER"
            ),

            # Handler Registration (Enhanced)
            BlenderSecurityRule(
                "Event Handler Registration",
                r"bpy\.app\.handlers\.(?:load_post|load_pre|save_post|save_pre|frame_change)\.append",
                "HIGH",
                "Event handler registration - persistent script execution",
                "BLENDER"
            ),
            BlenderSecurityRule(
                "Render Handler Registration",
                r"bpy\.app\.handlers\.(?:render_pre|render_post|render_cancel)\.append",
                "MEDIUM",
                "Render handler registration",
                "BLENDER"
            ),

            # Custom Properties (Enhanced)
            BlenderSecurityRule(
                "Custom Property Script Storage",
                r"\[['\"]\w+['\"]]\s*=.*(?:import|exec|eval)",
                "HIGH",
                "Script stored in custom property",
                "BLENDER"
            ),

            # Fake Addons
            BlenderSecurityRule(
                "Addon Registration",
                r"bpy\.utils\.(?:register_class|unregister_class|register_module)",
                "MEDIUM",
                "Addon registration - verify addon legitimacy",
                "BLENDER"
            ),
            BlenderSecurityRule(
                "Startup Script Installation",
                r"(?:startup|addons).*\.py.*(?:copy|write|create)",
                "HIGH",
                "Startup script installation - persistence mechanism",
                "BLENDER"
            ),

            # Advanced Blender API Abuse
            BlenderSecurityRule(
                "Text Block Manipulation",
                r"bpy\.data\.texts\.(?:new|remove|load)",
                "MEDIUM",
                "Text block manipulation - script injection vector",
                "BLENDER"
            ),
            BlenderSecurityRule(
                "Scene Property Manipulation",
                r"bpy\.context\.scene\[['\"]\w+['\"]]\s*=",
                "LOW",
                "Scene property modification",
                "BLENDER"
            ),

            # Suspicious String Patterns (Enhanced)
            BlenderSecurityRule(
                "Obfuscated Function Names",
                r"(?:chr\(\d+\)|ord\(|hex\(|oct\()",
                "MEDIUM",
                "Character manipulation functions - potential obfuscation",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "String Concatenation Obfuscation",
                r"['\"][^'\"]*['\"](?:\s*\+\s*['\"][^'\"]*['\"]){5,}",
                "MEDIUM",
                "Complex string concatenation - possible obfuscation",
                "OBFUSCATION"
            ),
            BlenderSecurityRule(
                "Compression/Decompression",
                r"(?:zlib\.|gzip\.|bz2\.|lzma\.)(?:compress|decompress)",
                "MEDIUM",
                "Data compression/decompression - potential payload unpacking",
                "OBFUSCATION"
            ),

            # Memory and Process Manipulation
            BlenderSecurityRule(
                "Memory Manipulation",
                r"(?:ctypes\.|mmap\.|struct\.)",
                "HIGH",
                "Memory manipulation - potential exploitation",
                "SYSTEM"
            ),
            BlenderSecurityRule(
                "Process Manipulation",
                r"(?:psutil\.|os\.(?:getpid|kill|waitpid))",
                "MEDIUM",
                "Process manipulation functions",
                "SYSTEM"
            ),

            # Anti-Analysis Patterns
            BlenderSecurityRule(
                "Debugger Detection",
                r"(?:debugger|pdb\.|trace\.|sys\.gettrace)",
                "MEDIUM",
                "Debugger detection - anti-analysis technique",
                "EVASION"
            ),
            BlenderSecurityRule(
                "VM Detection",
                r"(?:virtualbox|vmware|qemu|xen|sandbox)",
                "MEDIUM",
                "Virtual machine detection strings",
                "EVASION"
            )
        ]
        return rules

    def analyze_blend_file_security(self, context) -> Dict:
        """Comprehensive security analysis of the current Blender file"""
        results = {
            'auto_run_status': self._check_auto_run_setting(),
            'embedded_scripts': [],
            'drivers_analysis': [],
            'custom_properties': [],
            'addon_analysis': [],
            'overall_risk': 'LOW',
            'recommendations': [],
            'file_info': {
                'name': bpy.data.filepath,
                'has_scripts': len(bpy.data.texts) > 0,
                'script_count': len(bpy.data.texts),
                'object_count': len(bpy.data.objects)
            }
        }

        # Enhanced script detection and analysis
        results['embedded_scripts'] = self._detect_and_analyze_all_scripts(context)

        # Analyze drivers
        results['drivers_analysis'] = self._analyze_drivers()

        # Analyze custom properties
        results['custom_properties'] = self._analyze_custom_properties()

        # Check addons
        results['addon_analysis'] = self._analyze_addons()

        # Calculate overall risk
        results['overall_risk'] = self._calculate_overall_risk(results)

        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)

        return results

    def _detect_and_analyze_all_scripts(self, context) -> List[Dict]:
        """Enhanced script detection from multiple sources"""
        all_scripts = []

        # 1. Analyze text blocks
        for text in bpy.data.texts:
            content = text.as_string().strip()
            if content:
                # Check if it's actually Python code
                if self._is_python_script(content):
                    script_analysis = self.analyze_script(content, text.name)
                    script_analysis['location'] = 'Text Block'
                    script_analysis['source_type'] = 'text_block'
                    all_scripts.append(script_analysis)
                else:
                    # Still analyze for embedded scripts in non-Python files
                    embedded = self._extract_embedded_scripts(content, text.name)
                    all_scripts.extend(embedded)

        # 2. Analyze node group scripts (Geometry Nodes, Shader Nodes with script nodes)
        node_scripts = self._analyze_node_scripts()
        all_scripts.extend(node_scripts)

        # 3. Analyze frame change handlers and other event handlers
        handler_scripts = self._analyze_event_handlers()
        all_scripts.extend(handler_scripts)

        # 4. Check for scripts in custom properties
        prop_scripts = self._analyze_script_properties()
        all_scripts.extend(prop_scripts)

        return all_scripts

    def _is_python_script(self, content: str) -> bool:
        """Detect if content is Python code"""
        # Check for Python keywords and patterns
        python_indicators = [
            'import ', 'from ', 'def ', 'class ', 'if __name__',
            'bpy.', 'bmesh.', 'mathutils.', 'print(', 'range(',
            'try:', 'except:', 'for ', 'while ', 'with '
        ]

        # Count Python-like patterns
        matches = sum(1 for indicator in python_indicators if indicator in content)

        # Try to parse as Python
        try:
            ast.parse(content)
            return True
        except SyntaxError:
            # If it has Python patterns but syntax errors, still consider it suspicious
            return matches >= 2

        return matches >= 3

    def _extract_embedded_scripts(self, content: str, filename: str) -> List[Dict]:
        """Extract embedded Python scripts from non-Python files"""
        embedded_scripts = []

        # Look for base64 encoded Python
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(base64_pattern, content)

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if self._is_python_script(decoded):
                    script_analysis = self.analyze_script(decoded, f"{filename}_embedded_b64")
                    script_analysis['location'] = f'Embedded in {filename}'
                    script_analysis['source_type'] = 'base64_embedded'
                    script_analysis['encoding'] = 'base64'
                    embedded_scripts.append(script_analysis)
            except Exception:
                continue

        # Look for hex encoded Python
        hex_pattern = r'[0-9a-fA-F]{80,}'
        hex_matches = re.findall(hex_pattern, content)

        for match in hex_matches:
            try:
                decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                if self._is_python_script(decoded):
                    script_analysis = self.analyze_script(decoded, f"{filename}_embedded_hex")
                    script_analysis['location'] = f'Embedded in {filename}'
                    script_analysis['source_type'] = 'hex_embedded'
                    script_analysis['encoding'] = 'hexadecimal'
                    embedded_scripts.append(script_analysis)
            except Exception:
                continue

        return embedded_scripts

    def _analyze_node_scripts(self) -> List[Dict]:
        """Analyze scripts in node groups"""
        node_scripts = []

        # Check all node groups
        for node_group in bpy.data.node_groups:
            for node in node_group.nodes:
                # Script nodes in geometry nodes
                if hasattr(node, 'script') and node.script:
                    content = node.script.as_string()
                    if content.strip():
                        script_analysis = self.analyze_script(content, f"Node_{node.name}")
                        script_analysis['location'] = f'Node Group: {node_group.name}'
                        script_analysis['source_type'] = 'node_script'
                        node_scripts.append(script_analysis)

                # Check for embedded scripts in node properties
                if hasattr(node, 'inputs'):
                    for input_socket in node.inputs:
                        if hasattr(input_socket, 'default_value') and isinstance(input_socket.default_value, str):
                            if len(input_socket.default_value) > 50 and self._is_python_script(input_socket.default_value):
                                script_analysis = self.analyze_script(input_socket.default_value, f"Node_Input_{node.name}")
                                script_analysis['location'] = f'Node Input: {node_group.name}.{node.name}'
                                script_analysis['source_type'] = 'node_input'
                                node_scripts.append(script_analysis)

        return node_scripts

    def _analyze_event_handlers(self) -> List[Dict]:
        """Analyze registered event handlers"""
        handler_scripts = []

        # Check various handler types
        handler_types = [
            ('load_post', bpy.app.handlers.load_post),
            ('load_pre', bpy.app.handlers.load_pre),
            ('save_post', bpy.app.handlers.save_post),
            ('save_pre', bpy.app.handlers.save_pre),
            ('frame_change_post', bpy.app.handlers.frame_change_post),
            ('frame_change_pre', bpy.app.handlers.frame_change_pre),
            ('render_post', bpy.app.handlers.render_post),
            ('render_pre', bpy.app.handlers.render_pre),
        ]

        for handler_name, handler_list in handler_types:
            for handler_func in handler_list:
                try:
                    # Get source code of the handler function
                    import inspect
                    source = inspect.getsource(handler_func)

                    script_analysis = self.analyze_script(source, f"Handler_{handler_name}")
                    script_analysis['location'] = f'Event Handler: {handler_name}'
                    script_analysis['source_type'] = 'event_handler'
                    script_analysis['handler_type'] = handler_name
                    handler_scripts.append(script_analysis)

                except Exception:
                    # Handler might be compiled or not accessible
                    continue

        return handler_scripts

    def _analyze_script_properties(self) -> List[Dict]:
        """Analyze custom properties that contain scripts"""
        script_props = []

        def check_properties_for_scripts(item, item_type, item_name):
            if hasattr(item, 'keys'):
                for key in item.keys():
                    if key.startswith('_'):  # Custom properties
                        value = str(item[key])
                        if len(value) > 30 and self._is_python_script(value):
                            script_analysis = self.analyze_script(value, f"Property_{key}")
                            script_analysis['location'] = f'{item_type} Property: {item_name}.{key}'
                            script_analysis['source_type'] = 'custom_property'
                            script_props.append(script_analysis)

        # Check all data types for script properties
        for obj in bpy.data.objects:
            check_properties_for_scripts(obj, 'Object', obj.name)

            # Check mesh data
            if obj.type == 'MESH' and obj.data:
                check_properties_for_scripts(obj.data, 'Mesh', obj.data.name)

            # Check armature bones
            if obj.type == 'ARMATURE' and obj.data and obj.data.bones:
                for bone in obj.data.bones:
                    check_properties_for_scripts(bone, 'Bone', f"{obj.name}.{bone.name}")

        # Check materials
        for mat in bpy.data.materials:
            check_properties_for_scripts(mat, 'Material', mat.name)

        # Check scenes
        for scene in bpy.data.scenes:
            check_properties_for_scripts(scene, 'Scene', scene.name)

        return script_props

    def analyze_script(self, script_content: str, filename: str = "unknown") -> Dict:
        """Enhanced script analysis with Blender-specific checks"""
        results = {
            'filename': filename,
            'risk_level': 'LOW',
            'issues': [],
            'suspicious_imports': [],
            'obfuscation_score': 0,
            'network_activity': False,
            'system_access': False,
            'hash': hashlib.sha256(script_content.encode()).hexdigest(),
            'size': len(script_content),
            'line_count': len(script_content.split('\n'))
        }

        # Pattern-based analysis
        lines = script_content.split('\n')
        for i, line in enumerate(lines, 1):
            for rule in self.security_rules:
                matches = rule.pattern.findall(line)
                if matches:
                    issue = {
                        'type': rule.name,
                        'severity': rule.severity,
                        'description': rule.description,
                        'category': rule.category,
                        'line': i,
                        'code': line.strip()[:100],  # Limit displayed code
                        'matches': matches if isinstance(matches[0], str) else []
                    }
                    results['issues'].append(issue)

                    # Update flags
                    if rule.category == 'NETWORK':
                        results['network_activity'] = True
                    elif rule.category in ['SYSTEM', 'SHELL']:
                        results['system_access'] = True
                    elif rule.category == 'OBFUSCATION':
                        results['obfuscation_score'] += 1

                    # Update overall risk level
                    if rule.severity == 'CRITICAL':
                        results['risk_level'] = 'CRITICAL'
                    elif rule.severity == 'HIGH' and results['risk_level'] not in ['CRITICAL']:
                        results['risk_level'] = 'HIGH'
                    elif rule.severity == 'MEDIUM' and results['risk_level'] in ['LOW']:
                        results['risk_level'] = 'MEDIUM'

        # AST-based analysis
        try:
            tree = ast.parse(script_content)
            ast_results = self._analyze_ast_enhanced(tree)

            # Check for suspicious imports
            for imp in ast_results.get('imports', []):
                if any(suspicious in imp for suspicious in self.suspicious_imports):
                    results['suspicious_imports'].append(imp)

        except SyntaxError as e:
            results['issues'].append({
                'type': 'SYNTAX_ERROR',
                'severity': 'LOW',
                'description': f'Syntax error: {str(e)}',
                'category': 'SYNTAX',
                'line': getattr(e, 'lineno', 0),
                'code': ''
            })

        return results

    def _analyze_ast_enhanced(self, tree: ast.AST) -> Dict:
        """Enhanced AST analysis for Blender-specific patterns"""
        results = {
            'imports': [],
            'function_calls': [],
            'string_literals': [],
            'variable_names': [],
            'blender_api_usage': [],
            'complexity_score': 0
        }

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                # Handle imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        results['imports'].append(alias.name)
                else:  # ImportFrom
                    module = node.module or ''
                    for alias in node.names:
                        full_name = f"{module}.{alias.name}" if module else alias.name
                        results['imports'].append(full_name)

            elif isinstance(node, ast.Call):
                # Track function calls
                func_name = self._get_function_name(node.func)
                if func_name:
                    results['function_calls'].append(func_name)
                    if 'bpy.' in func_name:
                        results['blender_api_usage'].append(func_name)

            elif isinstance(node, ast.Str):
                # Analyze string literals
                if len(node.s) > 50:
                    results['string_literals'].append({
                        'content': node.s[:50] + "...",
                        'length': len(node.s),
                        'is_base64_like': self._is_base64_like(node.s)
                    })

            elif isinstance(node, ast.Name):
                # Track variable names for obfuscation detection
                if len(node.id) == 1 or node.id.lower() in ['l', 'o', 'i1', 'll']:
                    results['variable_names'].append(node.id)

        # Calculate complexity score
        results['complexity_score'] = (
            len(results['function_calls']) +
            len(results['imports']) +
            len([s for s in results['string_literals'] if s['length'] > 100])
        )

        return results

    def _check_auto_run_setting(self) -> Dict:
        """Check Blender's Auto Run Python Scripts setting"""
        auto_run_enabled = bpy.context.preferences.filepaths.use_scripts_auto_execute
        return {
            'enabled': auto_run_enabled,
            'risk_level': 'HIGH' if auto_run_enabled else 'LOW',
            'recommendation': 'Disable auto-run for security' if auto_run_enabled else 'Good - auto-run is disabled'
        }

    def _analyze_drivers(self) -> List[Dict]:
        """Analyze driver expressions for malicious code"""
        driver_issues = []

        # Check all objects for drivers
        for obj in bpy.data.objects:
            if obj.animation_data and obj.animation_data.drivers:
                for driver in obj.animation_data.drivers:
                    expr = driver.driver.expression
                    if expr.strip() and len(expr) > 10:  # Non-trivial expressions
                        analysis = self.analyze_script(expr, f"Driver on {obj.name}")
                        if analysis['issues']:
                            driver_issues.append({
                                'object': obj.name,
                                'expression': expr[:100],
                                'issues': analysis['issues'],
                                'risk_level': analysis['risk_level']
                            })

        return driver_issues

    def _analyze_custom_properties(self) -> List[Dict]:
        """Analyze custom properties for embedded scripts"""
        prop_issues = []

        def check_custom_props(item, item_type, item_name):
            if hasattr(item, 'keys'):
                for key in item.keys():
                    if key.startswith('_'):  # Custom properties start with underscore
                        value = str(item[key])
                        if len(value) > 50 and any(indicator in value for indicator in self.obfuscation_indicators):
                            prop_issues.append({
                                'type': item_type,
                                'name': item_name,
                                'property': key,
                                'value_preview': value[:100],
                                'suspicious': True
                            })

        # Check objects, bones, materials, etc.
        for obj in bpy.data.objects:
            check_custom_props(obj, 'Object', obj.name)
            if obj.pose and obj.pose.bones:
                for bone in obj.pose.bones:
                    check_custom_props(bone, 'Bone', f"{obj.name}.{bone.name}")

        for mat in bpy.data.materials:
            check_custom_props(mat, 'Material', mat.name)

        return prop_issues

    def _analyze_addons(self) -> List[Dict]:
        """Analyze installed addons for suspicious entries"""
        addon_issues = []

        # Get list of enabled addons
        enabled_addons = bpy.context.preferences.addons.keys()

        # Check for suspicious addon names or patterns
        suspicious_patterns = [
            r'temp_.*', r'test_.*', r'hack_.*', r'crack_.*',
            r'[a-f0-9]{8,}',  # Random hex strings
            r'^[a-z]{1,3}$'   # Very short names
        ]

        for addon_name in enabled_addons:
            is_suspicious = any(re.match(pattern, addon_name) for pattern in suspicious_patterns)

            if is_suspicious:
                addon_issues.append({
                    'name': addon_name,
                    'reason': 'Suspicious naming pattern',
                    'recommendation': 'Review addon source code'
                })

        return addon_issues

    def analyze_addon_security(self, addon_name: str) -> Dict:
        """Analyze security of a specific addon"""
        results = {
            'addon_name': addon_name,
            'risk_level': 'LOW',
            'issues': [],
            'suspicious_imports': [],
            'script_files': [],
            'addon_info': {},
            'permissions_requested': [],
            'network_activity': False,
            'system_access': False
        }

        try:
            # Get addon module info
            addon_info = self.get_addon_info(addon_name)
            results['addon_info'] = addon_info

            # Find addon files
            addon_files = self._find_addon_files(addon_name)

            # Analyze each Python file in the addon
            for file_path in addon_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Analyze the script
                    script_analysis = self.analyze_script(content, file_path)

                    # Merge results
                    results['issues'].extend(script_analysis['issues'])
                    results['suspicious_imports'].extend(script_analysis['suspicious_imports'])
                    results['script_files'].append({
                        'file': file_path,
                        'risk_level': script_analysis['risk_level'],
                        'issue_count': len(script_analysis['issues'])
                    })

                    if script_analysis['network_activity']:
                        results['network_activity'] = True
                    if script_analysis['system_access']:
                        results['system_access'] = True

                    # Update overall risk level
                    if script_analysis['risk_level'] == 'CRITICAL':
                        results['risk_level'] = 'CRITICAL'
                    elif script_analysis['risk_level'] == 'HIGH' and results['risk_level'] not in ['CRITICAL']:
                        results['risk_level'] = 'HIGH'
                    elif script_analysis['risk_level'] == 'MEDIUM' and results['risk_level'] in ['LOW']:
                        results['risk_level'] = 'MEDIUM'

                except Exception as e:
                    print(f"Error analyzing addon file {file_path}: {e}")
                    continue

            # Check for addon-specific security patterns
            self._check_addon_specific_risks(results)

        except Exception as e:
            print(f"Error analyzing addon {addon_name}: {e}")
            results['issues'].append({
                'type': 'ANALYSIS_ERROR',
                'severity': 'LOW',
                'description': f'Error during analysis: {str(e)}',
                'category': 'ERROR',
                'line': 0,
                'code': ''
            })

        return results

    def get_addon_info(self, addon_name: str) -> Dict:
        """Get addon information including developer contact details"""
        addon_info = {
            'name': addon_name,
            'wiki_url': '',
            'tracker_url': '',
            'author': '',
            'version': '',
            'description': ''
        }

        try:
            # Try to get addon module
            import sys
            if addon_name in sys.modules:
                addon_module = sys.modules[addon_name]

                # Check for bl_info
                if hasattr(addon_module, 'bl_info'):
                    bl_info = addon_module.bl_info
                    addon_info.update({
                        'name': bl_info.get('name', addon_name),
                        'wiki_url': bl_info.get('wiki_url', ''),
                        'tracker_url': bl_info.get('tracker_url', ''),
                        'author': bl_info.get('author', ''),
                        'version': str(bl_info.get('version', '')),
                        'description': bl_info.get('description', '')
                    })

            # Try alternative method using addon preferences
            try:
                addon_prefs = bpy.context.preferences.addons.get(addon_name)
                if addon_prefs and hasattr(addon_prefs, 'module'):
                    module = addon_prefs.module
                    if hasattr(module, 'bl_info'):
                        bl_info = module.bl_info
                        addon_info.update({
                            'name': bl_info.get('name', addon_name),
                            'wiki_url': bl_info.get('wiki_url', ''),
                            'tracker_url': bl_info.get('tracker_url', ''),
                            'author': bl_info.get('author', ''),
                            'version': str(bl_info.get('version', '')),
                            'description': bl_info.get('description', '')
                        })
            except:
                pass

        except Exception as e:
            print(f"Error getting addon info for {addon_name}: {e}")

        return addon_info

    def _find_addon_files(self, addon_name: str) -> List[str]:
        """Find all Python files belonging to an addon"""
        addon_files = []

        try:
            import os
            import sys

            # Method 1: Check addon paths with proper script_paths() handling
            addon_paths = []

            # Try multiple methods to get addon paths
            try:
                # Method 1a: Try the newer method first (no arguments) for Blender 4.4+
                script_paths = bpy.utils.script_paths()
                for path in script_paths:
                    addon_dir = os.path.join(path, "addons")
                    if os.path.exists(addon_dir):
                        addon_paths.append(addon_dir)
                print(f"BlendScan: Found {len(addon_paths)} addon paths using script_paths()")

            except (TypeError, AttributeError) as e:
                print(f"BlendScan: script_paths() method failed: {e}")

                # Method 1b: Try user resource method
                try:
                    user_scripts = bpy.utils.user_resource('SCRIPTS')
                    if user_scripts:
                        user_addons = os.path.join(user_scripts, "addons")
                        if os.path.exists(user_addons):
                            addon_paths.append(user_addons)
                            print(f"BlendScan: Added user addon path: {user_addons}")
                except Exception as e2:
                    print(f"BlendScan: user_resource method failed: {e2}")

                # Method 1c: Try system resource method
                try:
                    system_scripts = bpy.utils.system_resource('SCRIPTS')
                    if system_scripts:
                        system_addons = os.path.join(system_scripts, "addons")
                        if os.path.exists(system_addons):
                            addon_paths.append(system_addons)
                            print(f"BlendScan: Added system addon path: {system_addons}")
                except Exception as e3:
                    print(f"BlendScan: system_resource method failed: {e3}")

            # Method 1d: Check common Blender addon locations as fallback
            if not addon_paths:
                common_paths = []

                # Get Blender executable location and derive addon paths
                try:
                    blender_path = bpy.app.binary_path
                    if blender_path:
                        blender_dir = os.path.dirname(os.path.dirname(blender_path))
                        potential_addon_paths = [
                            os.path.join(blender_dir, "scripts", "addons"),
                            os.path.join(blender_dir, "scripts", "addons_contrib"),
                        ]
                        for path in potential_addon_paths:
                            if os.path.exists(path):
                                common_paths.append(path)
                except Exception as e4:
                    print(f"BlendScan: Could not derive paths from binary: {e4}")

                # Check user profile locations
                try:
                    import os.path
                    user_home = os.path.expanduser("~")
                    potential_user_paths = [
                        os.path.join(user_home, "AppData", "Roaming", "Blender Foundation", "Blender", "*", "scripts", "addons"),
                        os.path.join(user_home, ".config", "blender", "*", "scripts", "addons"),
                        os.path.join(user_home, "Library", "Application Support", "Blender", "*", "scripts", "addons"),
                    ]

                    import glob
                    for pattern in potential_user_paths:
                        for path in glob.glob(pattern):
                            if os.path.exists(path):
                                common_paths.append(path)

                except Exception as e5:
                    print(f"BlendScan: Could not check user profile paths: {e5}")

                addon_paths.extend(common_paths)
                if common_paths:
                    print(f"BlendScan: Found {len(common_paths)} addon paths using fallback methods")

            # Search for addon files in all found paths
            for addon_path in addon_paths:
                if not os.path.exists(addon_path):
                    continue

                print(f"BlendScan: Searching in addon path: {addon_path}")

                # Check for addon directory
                addon_dir = os.path.join(addon_path, addon_name)
                if os.path.isdir(addon_dir):
                    print(f"BlendScan: Found addon directory: {addon_dir}")
                    # Find all .py files recursively
                    for root, dirs, files in os.walk(addon_dir):
                        for file in files:
                            if file.endswith('.py'):
                                addon_files.append(os.path.join(root, file))

                # Check for single-file addon
                single_file = os.path.join(addon_path, f"{addon_name}.py")
                if os.path.isfile(single_file):
                    print(f"BlendScan: Found single-file addon: {single_file}")
                    addon_files.append(single_file)

            # Method 2: Check if addon is loaded as a module
            if not addon_files and addon_name in sys.modules:
                print(f"BlendScan: Addon '{addon_name}' found in sys.modules, getting file path")
                try:
                    addon_module = sys.modules[addon_name]
                    if hasattr(addon_module, '__file__') and addon_module.__file__:
                        module_file = addon_module.__file__
                        print(f"BlendScan: Module file: {module_file}")

                        if module_file.endswith('.pyc'):
                            # Try to find the .py file
                            py_file = module_file[:-1]  # Remove 'c' from .pyc
                            if os.path.exists(py_file):
                                addon_files.append(py_file)
                            else:
                                addon_files.append(module_file)
                        else:
                            addon_files.append(module_file)

                        # If it's in a package, get the directory
                        module_dir = os.path.dirname(module_file)
                        if os.path.isdir(module_dir):
                            print(f"BlendScan: Scanning module directory: {module_dir}")
                            for root, dirs, files in os.walk(module_dir):
                                for file in files:
                                    if file.endswith('.py'):
                                        full_path = os.path.join(root, file)
                                        if full_path not in addon_files:
                                            addon_files.append(full_path)
                except Exception as e:
                    print(f"BlendScan: Error getting module file for {addon_name}: {e}")

            # Method 3: Check addon_utils for more comprehensive search
            try:
                import addon_utils
                print(f"BlendScan: Using addon_utils to find '{addon_name}'")

                for addon_module_info in addon_utils.modules():
                    if addon_module_info and hasattr(addon_module_info, '__name__'):
                        module_name = addon_module_info.__name__

                        # Handle bl_ext prefix for extensions
                        clean_name = module_name
                        if clean_name.startswith('bl_ext.'):
                            clean_name = clean_name[7:]

                        if clean_name == addon_name or module_name == addon_name:
                            print(f"BlendScan: Found matching addon module: {module_name}")
                            if hasattr(addon_module_info, '__file__') and addon_module_info.__file__:
                                module_file = addon_module_info.__file__
                                if module_file not in addon_files:
                                    addon_files.append(module_file)

                                # Get directory files if it's a package
                                module_dir = os.path.dirname(module_file)
                                if os.path.isdir(module_dir):
                                    for root, dirs, files in os.walk(module_dir):
                                        for file in files:
                                            if file.endswith('.py'):
                                                full_path = os.path.join(root, file)
                                                if full_path not in addon_files:
                                                    addon_files.append(full_path)
                            break

            except Exception as e:
                print(f"BlendScan: Error using addon_utils for {addon_name}: {e}")

            # Method 4: Check enabled addons preferences for path hints
            try:
                if addon_name in bpy.context.preferences.addons.keys():
                    addon_pref = bpy.context.preferences.addons[addon_name]
                    if hasattr(addon_pref, 'module') and hasattr(addon_pref.module, '__file__'):
                        module_file = addon_pref.module.__file__
                        if module_file and module_file not in addon_files:
                            addon_files.append(module_file)

                            # Check directory
                            module_dir = os.path.dirname(module_file)
                            if os.path.isdir(module_dir):
                                for root, dirs, files in os.walk(module_dir):
                                    for file in files:
                                        if file.endswith('.py'):
                                            full_path = os.path.join(root, file)
                                            if full_path not in addon_files:
                                                addon_files.append(full_path)
            except Exception as e:
                print(f"BlendScan: Error checking addon preferences for {addon_name}: {e}")

        except Exception as e:
            print(f"BlendScan: Error finding addon files for {addon_name}: {e}")
            import traceback
            print(f"BlendScan: Traceback: {traceback.format_exc()}")

        # Remove duplicates and sort
        addon_files = list(set(addon_files))
        addon_files.sort()

        print(f"BlendScan: Found {len(addon_files)} files for addon '{addon_name}': {addon_files[:3]}{'...' if len(addon_files) > 3 else ''}")

        return addon_files

    def _check_addon_specific_risks(self, results: Dict):
        """Check for addon-specific security risks"""
        addon_name = results['addon_name']

        # Check for suspicious addon naming patterns
        suspicious_name_patterns = [
            r'^temp_',
            r'^test_',
            r'^crack_',
            r'^hack_',
            r'^[a-f0-9]{8,}$',  # Random hex strings
            r'^[a-z]{1,3}$'     # Very short names
        ]

        for pattern in suspicious_name_patterns:
            if re.match(pattern, addon_name, re.IGNORECASE):
                results['issues'].append({
                    'type': 'SUSPICIOUS_ADDON_NAME',
                    'severity': 'MEDIUM',
                    'description': f'Addon name matches suspicious pattern: {pattern}',
                    'category': 'ADDON',
                    'line': 0,
                    'code': f'Addon name: {addon_name}'
                })

        # Check for missing or suspicious bl_info
        addon_info = results['addon_info']
        if not addon_info.get('author'):
            results['issues'].append({
                'type': 'MISSING_AUTHOR_INFO',
                'severity': 'LOW',
                'description': 'Addon missing author information',
                'category': 'ADDON',
                'line': 0,
                'code': 'bl_info missing author field'
            })

        if not addon_info.get('description'):
            results['issues'].append({
                'type': 'MISSING_DESCRIPTION',
                'severity': 'LOW',
                'description': 'Addon missing description',
                'category': 'ADDON',
                'line': 0,
                'code': 'bl_info missing description field'
            })

        # Check for network-related permissions in addon
        if results['network_activity'] and not addon_info.get('wiki_url') and not addon_info.get('tracker_url'):
            results['issues'].append({
                'type': 'NETWORK_ACCESS_NO_CONTACT',
                'severity': 'HIGH',
                'description': 'Addon has network access but no developer contact info',
                'category': 'ADDON',
                'line': 0,
                'code': 'Network activity detected'
            })

        # Escalate risk if multiple concerning factors
        high_risk_factors = sum([
            results['network_activity'],
            results['system_access'],
            len([i for i in results['issues'] if i['severity'] == 'CRITICAL']) > 0,
            not addon_info.get('author'),
            len(results['suspicious_imports']) > 3
        ])

        if high_risk_factors >= 3 and results['risk_level'] not in ['CRITICAL']:
            results['risk_level'] = 'HIGH'
            results['issues'].append({
                'type': 'MULTIPLE_RISK_FACTORS',
                'severity': 'HIGH',
                'description': f'Multiple security risk factors detected ({high_risk_factors})',
                'category': 'ADDON',
                'line': 0,
                'code': 'Combined risk assessment'
            })

    def _calculate_overall_risk(self, results: Dict) -> str:
        """Calculate overall risk level based on all analyses"""
        risk_factors = []

        # Check auto-run setting
        if results['auto_run_status']['enabled']:
            risk_factors.append('HIGH')

        # Check embedded scripts
        for script in results['embedded_scripts']:
            risk_factors.append(script['risk_level'])

        # Check drivers
        for driver in results['drivers_analysis']:
            risk_factors.append(driver['risk_level'])

        # Determine highest risk
        if 'CRITICAL' in risk_factors:
            return 'CRITICAL'
        elif 'HIGH' in risk_factors:
            return 'HIGH'
        elif 'MEDIUM' in risk_factors:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if results['auto_run_status']['enabled']:
            recommendations.append("Disable 'Auto Run Python Scripts' in Preferences > Save & Load")

        if results['embedded_scripts']:
            high_risk_scripts = [s for s in results['embedded_scripts'] if s['risk_level'] in ['HIGH', 'CRITICAL']]
            if high_risk_scripts:
                recommendations.append(f"Review {len(high_risk_scripts)} high-risk embedded scripts")

        if results['drivers_analysis']:
            recommendations.append("Check driver expressions in Graph Editor for malicious code")

        if results['custom_properties']:
            recommendations.append("Review custom properties for embedded malicious data")

        if results['addon_analysis']:
            recommendations.append("Review suspicious addons and remove if unnecessary")

        # General recommendations
        recommendations.extend([
            "Only open .blend files from trusted sources",
            "Use antivirus software to scan files before opening",
            "Consider using virtual machines for untrusted files",
            "Keep Blender updated to latest version",
            "Regular backups to prevent data loss"
        ])

        return recommendations

    def _get_function_name(self, node) -> Optional[str]:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_function_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return None

    def _is_base64_like(self, s: str) -> bool:
        """Check if string looks like base64 encoded data"""
        if len(s) < 20:
            return False

        # Check for base64 character set and padding
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' )
        return (
            len(set(s) - base64_chars) == 0 and
            s.count('=') <= 2 and
            len(s) % 4 == 0
        )