# BlendScan 🛡️

**Comprehensive security analysis for Blender files and scripts with auto-protection**

[![Blender](https://img.shields.io/badge/Blender-4.4.3+-orange.svg?style=flat&logo=blender)](https://www.blender.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=flat&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green.svg?style=flat)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Critical-red.svg?style=flat&logo=shield)](https://github.com/kents00/blendscan)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue.svg?style=flat)](https://gitlab.com/kents00/blendscan)

## 📋 Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Security Features](#security-features)
- [Interface](#interface)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## 🛡️ Introduction

BlendScan is a comprehensive security addon for Blender that protects users from malicious `.blend` files and embedded scripts. With the rise of malware targeting 3D artists through infected Blender files, BlendScan provides real-time protection, automated threat detection, and secure script execution.

**⚠️ Why BlendScan?**
- Malicious `.blend` files can contain embedded Python scripts that execute automatically
- Scripts can steal data, install malware, or damage your system
- BlendScan prevents automatic execution and analyzes content before allowing scripts to run

## ✨ Features

### 🔍 **Comprehensive Threat Detection**
- **Real-time Script Analysis** - Analyzes Python scripts before execution
- **Embedded Script Detection** - Finds hidden scripts in text blocks, nodes, and properties
- **Base64/Hex Decoding** - Detects obfuscated malicious payloads
- **Driver Expression Analysis** - Scans animation drivers for malicious code
- **Custom Property Scanning** - Checks for scripts hidden in object properties

### 🛡️ **Auto-Protection System**
- **Auto-Run Blocking** - Automatically disables "Auto Run Python Scripts"
- **Ctrl+P Override** - Secure script execution with security analysis
- **Countdown Warning** - 10-second warning before closing on critical threats
- **Continuous Monitoring** - Real-time monitoring of text block changes

### 📊 **Risk Assessment**
- **4-Level Risk System** - Low, Medium, High, Critical
- **Pattern-Based Detection** - 50+ security rules for threat identification
- **Network Activity Detection** - Identifies scripts making external connections
- **System Access Monitoring** - Detects file system and command execution

### 🎯 **Blender-Specific Protection**
- **Event Handler Analysis** - Scans load/save/render handlers
- **Node Script Detection** - Analyzes Geometry/Shader node scripts
- **Addon Verification** - Checks for suspicious addon installations
- **Driver Namespace Protection** - Monitors driver namespace manipulation

## 📦 Installation

### Method 1: Manual Installation
1. Download the latest release from [GitLab](https://gitlab.com/kents00/blendscan)
2. Open Blender and go to `Edit > Preferences > Add-ons`
3. Click `Install...` and select the BlendScan zip file
4. Enable the addon by checking the box next to "Security: BlendScan"

### Method 2: Development Installation
```bash
git clone https://gitlab.com/kents00/blendscan.git
cd blendscan
# Copy to Blender addons directory
cp -r . ~/.config/blender/4.4/scripts/addons/blendscan/
```

### Requirements
- **Blender 4.4.3+** (tested on latest versions)
- **Python 3.10+** (included with Blender)
- **Operating System**: Windows, macOS, Linux

## 🚀 Usage

### Basic Protection (Automatic)
BlendScan works automatically once installed:
- **Auto-Run Disabled** - Prevents automatic script execution
- **File Load Scanning** - Analyzes files when opened
- **Real-time Monitoring** - Watches for new/modified scripts

### Manual Security Scanning

#### Text Editor Panel
1. Open the **Text Editor** workspace
2. Navigate to **Properties Panel** > **BlendScan** tab
3. Use available tools:
   - **Analyze Script** - Scan current text block
   - **Run Script (Secure)** - Execute with security check
   - **Scan All Scripts** - Comprehensive file analysis

#### Keyboard Shortcuts
- **Ctrl+P** - Secure script execution (overrides default)
- Scripts are analyzed before execution with automatic blocking of high-risk code

### Security Dialog
When threats are detected:
```
⚠️ SECURITY THREAT DETECTED
Blender will close in 10 seconds

Risk Level: CRITICAL
• Malicious Scripts Found: script.py
  - Base64 Decoding
  - System Command Execution
• Only open files from trusted sources
```

## 🔒 Security Features

### Threat Detection Categories

| Category | Risk Level | Examples |
|----------|------------|----------|
| **Code Execution** | Critical | `exec()`, `eval()`, `compile()` |
| **System Access** | Critical | `os.system()`, `subprocess.call()` |
| **Network Activity** | High | HTTP requests, socket connections |
| **File Operations** | High | File deletion, directory manipulation |
| **Obfuscation** | High | Base64 encoding, hex strings |
| **Blender API Abuse** | Medium | Handler registration, driver manipulation |

### Protection Levels

#### 🔴 **Critical Threats**
- **Immediate Closure** - Blender closes automatically
- **10-Second Warning** - Countdown dialog with threat details
- **No Execution** - Scripts are completely blocked

#### 🟡 **High/Medium Threats**
- **Warning Messages** - Console and UI notifications
- **Optional Execution** - User can choose to proceed
- **Detailed Analysis** - Full threat breakdown

#### 🟢 **Low Risk**
- **Console Logging** - Informational messages
- **Normal Execution** - Scripts run normally
- **Background Monitoring** - Continuous observation

## 🖥️ Interface

### Text Editor Panel
```
┌─ BlendScan Security ─────────────┐
│ Auto-Run Scripts: DISABLED ✓     │
│ [Disable Auto-Run (Recommended)] │
├─ Script: script.py ──────────────┤
│ [Analyze Script]                 │
│ [Run Script (Secure)]            │
│ [Run Script (Unsecured)] ⚠️      │
│ [Bypass All Security] ❌         │
├─ Global Security ────────────────┤
│ [Scan All Scripts]               │
│ Monitoring Active ✓              │
└──────────────────────────────────┘
```

### Console Output Example
```
BlendScan: Analyzing script 'malicious.py' before execution...
BLOCKING SCRIPT EXECUTION: malicious.py
Risk Level: CRITICAL
Security Issues:
  Line 15: Base64 Decoding (CRITICAL)
    Code: decoded = base64.b64decode(payload)
  Line 23: System Command Execution (CRITICAL)
    Code: os.system(f"rm -rf {user_home}")
```

## ⚙️ Configuration

### Auto-Run Setting
```python
# Automatically disabled on addon installation
bpy.context.preferences.filepaths.use_scripts_auto_execute = False
```

### Custom Security Rules
Add custom patterns to `analyzer.py`:
```python
BlenderSecurityRule(
    "Custom Pattern",
    r"suspicious_function\s*\(",
    "HIGH",
    "Custom security rule description",
    "CUSTOM"
)
```

### Monitoring Intervals
```python
# Continuous monitoring every 2 seconds
bpy.app.timers.register(continuous_monitoring, first_interval=2.0)
```

## 🤝 Contributing

We welcome contributions to improve BlendScan's security capabilities!

### Development Setup
```bash
git clone https://gitlab.com/kents00/blendscan.git
cd blendscan
# Install in development mode
ln -s $(pwd) ~/.config/blender/4.4/scripts/addons/blendscan
```

### Adding Security Rules
1. Edit `analyzer.py`
2. Add new `BlenderSecurityRule` objects
3. Test with known malicious patterns
4. Submit merge request

### Reporting Vulnerabilities
- **Security Issues**: Email security@example.com
- **Bug Reports**: Create GitLab issue
- **Feature Requests**: Use GitLab discussions

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help
- **Documentation**: [GitLab Wiki](https://gitlab.com/kents00/blendscan/-/wikis/home)
- **Issues**: [GitLab Issues](https://gitlab.com/kents00/blendscan/-/issues)
- **Discussions**: [GitLab Discussions](https://gitlab.com/kents00/blendscan/-/discussions)

### Author
**Kent Edoloverio**
- GitLab: [@kents00](https://gitlab.com/kents00)
- Email: kent@example.com

### Acknowledgments
- Blender Foundation for the amazing 3D software
- Security researchers identifying .blend file vulnerabilities
- Open source community for security best practices

---

⚠️ **Security Notice**: Always scan files from unknown sources. BlendScan provides protection but cannot guarantee 100% security against all threats.
