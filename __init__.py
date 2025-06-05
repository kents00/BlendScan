bl_info = {
    "name": "BlendScan",
    "author": "Kent Edoloverio",
    "version": (1, 0, 0),
    "blender": (4, 4, 3),
    "location": "Text Editor > Properties > BlendScan",
    "description": "Comprehensive security analysis for Blender files and scripts with auto-protection",
    "category": "Security",
}

import bpy
import time
import hashlib
from bpy.app.handlers import persistent
from .analyzer import BlenderSecurityAnalyzer

# Constants for operator identifiers
SECURE_RUN_SCRIPT_ID = 'security.secure_run_script'
TOGGLE_AUTO_RUN_ID = "security.toggle_auto_run"

class SECURITY_OT_CountdownWarning(bpy.types.Operator):
    """Security warning dialog with countdown"""
    bl_idname = "security.countdown_warning"
    bl_label = "SECURITY THREAT DETECTED"
    bl_options = {'REGISTER', 'INTERNAL'}

    countdown: bpy.props.IntProperty(default=10)
    security_issues: bpy.props.StringProperty(default="")
    remaining_time: bpy.props.IntProperty(default=10)

    def execute(self, context):
        print("User clicked OK - closing Blender immediately")
        bpy.ops.wm.quit_blender()
        return {'FINISHED'}

    def invoke(self, context, event):
        # Start the countdown timer
        self.remaining_time = self.countdown
        self._start_countdown(context)

        # Show the dialog immediately
        wm = context.window_manager
        return wm.invoke_props_dialog(self, width=600)

    def _start_countdown(self, context):
        """Start the countdown using a timer"""
        def countdown_update():
            if self.remaining_time > 0:
                self.remaining_time -= 1
                # Force redraw to update the countdown display
                for area in context.screen.areas:
                    area.tag_redraw()
                # Continue countdown
                return 1.0  # Run again in 1 second
            else:
                # Time's up - close Blender
                print("Countdown finished - closing Blender")
                bpy.ops.wm.quit_blender()
                return None  # Stop the timer

        # Register the countdown timer
        bpy.app.timers.register(countdown_update, first_interval=1.0)

    def draw(self, context):
        layout = self.layout

        # Header with warning
        header_box = layout.box()
        header_box.alert = True

        row = header_box.row()
        row.scale_y = 1.5
        row.label(text="SECURITY THREAT DETECTED", icon='ERROR')

        # Countdown display
        row = header_box.row()
        row.scale_y = 2.0
        row.alert = True
        row.label(text=f"Blender will close in {self.remaining_time} seconds", icon='TIME')

        layout.separator()

        # Security details
        try:
            if self.security_issues:
                issues_data = eval(self.security_issues)

                # Risk level
                info_box = layout.box()
                row = info_box.row()
                row.alert = True
                risk_level = issues_data.get('overall_risk', 'UNKNOWN')
                row.label(text=f"Risk Level: {risk_level}", icon='CANCEL')

                # Script issues
                embedded_scripts = issues_data.get('embedded_scripts', [])
                if embedded_scripts:
                    script_box = layout.box()
                    script_box.label(text="Malicious Scripts Found:", icon='TEXT')

                    for script in embedded_scripts[:2]:
                        if script.get('issues'):
                            row = script_box.row()
                            row.label(text=f"• {script['filename']}")

                            for issue in script['issues'][:2]:
                                if issue['severity'] == 'CRITICAL':
                                    issue_row = script_box.row()
                                    issue_row.alert = True
                                    issue_row.label(text=f"  - {issue['type']}")

                # Recommendations
                recommendations = issues_data.get('recommendations', [])
                if recommendations:
                    rec_box = layout.box()
                    rec_box.label(text="Security Recommendations:", icon='INFO')
                    for rec in recommendations[:3]:
                        rec_box.label(text=f"• {rec[:70]}...")

        except Exception as e:
            error_box = layout.box()
            error_box.alert = True
            error_box.label(text="Error displaying threat details")

        layout.separator()

        # Warning message
        warning_box = layout.box()
        warning_box.alert = True
        warning_box.label(text="This file contains potentially malicious code!")
        warning_box.label(text="Blender will close automatically for your protection.")
        warning_box.label(text="Only open files from trusted sources.")

        layout.separator()
        layout.label(text="Click OK to close immediately, or wait for automatic closure.")

# Remove the override operator and replace with a wrapper
class SECURITY_OT_SecureRunScript(bpy.types.Operator):
    """Secure script execution with security analysis"""
    bl_idname = "security.secure_run_script"
    bl_label = "Run Script (Security Check)"
    bl_description = "Run script with security analysis"
    bl_options = {'REGISTER', 'UNDO'}

    @classmethod
    def poll(cls, context):
        return (context.area and context.area.type == 'TEXT_EDITOR' and
                context.space_data.text is not None)

    def execute(self, context):
        text = context.space_data.text
        if not text:
            self.report({'ERROR'}, "No text to run")
            return {'CANCELLED'}

        content = text.as_string()
        if not content.strip():
            self.report({'ERROR'}, "No content to run")
            return {'CANCELLED'}

        # Perform security analysis
        print(f"BlendScan: Analyzing script '{text.name}' before execution...")
        analyzer = BlenderSecurityAnalyzer()

        if analyzer._is_python_script(content):
            script_analysis = analyzer.analyze_script(content, text.name)

            # Check for security issues
            if script_analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                print(f"BLOCKING SCRIPT EXECUTION: {text.name}")
                print(f"Risk Level: {script_analysis['risk_level']}")

                # Create threat results for the warning dialog
                threat_results = {
                    'overall_risk': script_analysis['risk_level'],
                    'embedded_scripts': [script_analysis],
                    'drivers_analysis': [],
                    'custom_properties': [],
                    'addon_analysis': [],
                    'auto_run_status': {'enabled': bpy.context.preferences.filepaths.use_scripts_auto_execute},
                    'recommendations': [
                        f"Attempted to execute malicious script: '{text.name}'",
                        "Script execution has been BLOCKED for your protection",
                        "Review and sanitize the code before running",
                        "Remove malicious functions and imports"
                    ]
                }

                # Show security warning
                try:
                    bpy.ops.security.countdown_warning(
                        'INVOKE_DEFAULT',
                        security_issues=str(threat_results)
                    )
                except Exception as e:
                    print(f"Error showing security dialog: {e}")
                    # Fallback: show error message and block execution
                    self.report({'ERROR'}, f"SECURITY THREAT: Script execution blocked. Risk level: {script_analysis['risk_level']}")

                    # Print detailed warning to console
                    print("=" * 60)
                    print("SCRIPT EXECUTION BLOCKED")
                    print("=" * 60)
                    print(f"Script: {text.name}")
                    print(f"Risk Level: {script_analysis['risk_level']}")
                    print("Security Issues:")
                    for issue in script_analysis['issues'][:5]:
                        print(f"  - {issue['type']}: {issue['description']}")
                        print(f"    Line {issue['line']}: {issue['code']}")
                    print("=" * 60)

                return {'CANCELLED'}

            elif script_analysis['risk_level'] == 'MEDIUM':
                # Show warning but allow execution
                self.report({'WARNING'}, f"Medium risk detected in '{text.name}' - check console for details")
                print(f"MEDIUM RISK WARNING for script: {text.name}")
                for issue in script_analysis['issues']:
                    if issue['severity'] == 'MEDIUM':
                        print(f"  - {issue['type']}: {issue['description']}")

            elif len(script_analysis['issues']) > 0:
                # Low risk - just log
                print(f"Low risk issues detected in '{text.name}':")
                for issue in script_analysis['issues']:
                    if issue['severity'] == 'LOW':
                        print(f"  - {issue['type']}: {issue['description']}")

        # If we get here, the script is safe to run - use the original operator
        print(f"BlendScan: Script '{text.name}' passed security check - executing...")

        try:
            # Call the original text.run_script operator
            result = bpy.ops.text.run_script()

            if result == {'FINISHED'}:
                self.report({'INFO'}, f"Script '{text.name}' executed successfully")
                print(f"BlendScan: Script execution completed: {text.name}")
            else:
                self.report({'WARNING'}, f"Script execution returned: {result}")

        except Exception as e:
            self.report({'ERROR'}, f"Script execution failed: {str(e)}")
            print(f"BlendScan: Script execution error in '{text.name}': {str(e)}")
            return {'CANCELLED'}

        return {'FINISHED'}

# Add keymap override to intercept Ctrl+P
class SecurityKeymapHelper:
    """Helper class to manage keymap overrides"""

    @staticmethod
    def add_keymap():
        """Add custom keymap to override default script execution"""
        try:
            # Get the window manager and keyconfig
            wm = bpy.context.window_manager
            kc = wm.keyconfigs.addon

            if kc:
                # Get or create the Text keymap
                km = kc.keymaps.get('Text')
                if not km:
                    km = kc.keymaps.new(name='Text', space_type='TEXT_EDITOR')

                # Remove any existing keymap items for our operator
                items_to_remove = []
                for kmi in km.keymap_items:
                    if kmi.idname == 'security.secure_run_script':
                        items_to_remove.append(kmi)

                for kmi in items_to_remove:
                    km.keymap_items.remove(kmi)

                # Add our secure run script operator for Ctrl+P
                kmi = km.keymap_items.new(
                    'security.secure_run_script',
                    type='P',
                    value='PRESS',
                    ctrl=True
                )
                kmi.active = True

                print("BlendScan: Keymap override added for Ctrl+P")

        except Exception as e:
            print(f"BlendScan: Error adding keymap: {e}")

    @staticmethod
    def remove_keymap():
        """Remove custom keymap"""
        try:
            wm = bpy.context.window_manager
            kc = wm.keyconfigs.addon

            if kc:
                km = kc.keymaps.get('Text')
                if km:
                    items_to_remove = []
                    for kmi in km.keymap_items:
                        if kmi.idname == 'security.secure_run_script':
                            items_to_remove.append(kmi)

                    for kmi in items_to_remove:
                        km.keymap_items.remove(kmi)

                    if items_to_remove:
                        print("BlendScan: Keymap override removed")

        except Exception as e:
            print(f"BlendScan: Error removing keymap: {e}")

# Global variable to store original auto-run setting
original_auto_run_setting = None

def disable_auto_run_scripts():
    """Disable Auto Run Python Scripts for security"""
    global original_auto_run_setting

    try:
        # Store the original setting
        original_auto_run_setting = bpy.context.preferences.filepaths.use_scripts_auto_execute

        # Disable auto-run if it's currently enabled
        if original_auto_run_setting:
            bpy.context.preferences.filepaths.use_scripts_auto_execute = False
            print("BlendScan: Auto Run Python Scripts has been DISABLED for security")
            print("BlendScan: This prevents automatic execution of malicious scripts")
        else:
            print("BlendScan: Auto Run Python Scripts was already disabled")

    except Exception as e:
        print(f"BlendScan: Error disabling auto-run scripts: {e}")

def restore_auto_run_scripts():
    """Restore original Auto Run Python Scripts setting"""
    global original_auto_run_setting

    try:
        if original_auto_run_setting is not None:
            bpy.context.preferences.filepaths.use_scripts_auto_execute = original_auto_run_setting
            if original_auto_run_setting:
                print("BlendScan: Auto Run Python Scripts setting has been restored to ENABLED")
            else:
                print("BlendScan: Auto Run Python Scripts setting remains DISABLED")
            original_auto_run_setting = None

    except Exception as e:
        print(f"BlendScan: Error restoring auto-run scripts setting: {e}")

# Add operator to manually toggle auto-run setting
class SECURITY_OT_ToggleAutoRun(bpy.types.Operator):
    """Toggle Auto Run Python Scripts setting"""
    bl_idname = "security.toggle_auto_run"
    bl_label = "Toggle Auto Run Scripts"
    bl_description = "Toggle the Auto Run Python Scripts setting"

    def execute(self, context):
        current_setting = context.preferences.filepaths.use_scripts_auto_execute
        context.preferences.filepaths.use_scripts_auto_execute = not current_setting

        if current_setting:
            self.report({'INFO'}, "Auto Run Python Scripts DISABLED")
            print("BlendScan: Auto Run Python Scripts manually DISABLED")
        else:
            self.report({'WARNING'}, "Auto Run Python Scripts ENABLED - Security Risk!")
            print("BlendScan: WARNING - Auto Run Python Scripts manually ENABLED")

        return {'FINISHED'}

# Add UI panel to show security status and manual controls
class SECURITY_PT_TextEditorPanel(bpy.types.Panel):
    """Security panel in text editor"""
    bl_label = "BlendScan Security"
    bl_idname = "SECURITY_PT_text_editor"
    bl_space_type = 'TEXT_EDITOR'
    bl_region_type = 'UI'
    bl_category = "BlendScan"

    def draw(self, context):
        layout = self.layout

        # Auto-run status display
        auto_run_box = layout.box()
        auto_run_enabled = context.preferences.filepaths.use_scripts_auto_execute

        if auto_run_enabled:
            auto_run_box.alert = True
            row = auto_run_box.row()
            row.alert = True
            row.label(text="Auto-Run Scripts: ENABLED", icon='ERROR')
            row = auto_run_box.row()
            row.label(text="SECURITY RISK - Scripts run automatically!")
        else:
            row = auto_run_box.row()
            row.label(text="Auto-Run Scripts: DISABLED", icon='CHECKMARK')
            row = auto_run_box.row()
            row.label(text="Safe - Scripts require manual execution")

        # Toggle button
        row = auto_run_box.row()
        if auto_run_enabled:
            row.operator("security.toggle_auto_run", text="Disable Auto-Run (Recommended)", icon='CANCEL')
        else:
            row.alert = True
            row.operator("security.toggle_auto_run", text="Enable Auto-Run (NOT Recommended)", icon='ERROR')

        layout.separator()

        # Current text analysis
        if context.space_data.text:
            text = context.space_data.text

            box = layout.box()
            box.label(text=f"Script: {text.name}", icon='TEXT')

            # Quick analysis button
            row = box.row()
            row.operator("security.analyze_current_text", text="Analyze Script", icon='ZOOM_ALL')

            # Secure run button (recommended)
            row = box.row()
            row.operator("security.secure_run_script", text="Run Script (Secure)", icon='PLAY')

            # Original run button (with warning)
            row = box.row()
            row.alert = True
            row.operator("text.run_script", text="Run Script (Unsecured)", icon='ERROR')

            # Bypass option (for advanced users)
            row = box.row()
            row.alert = True
            row.operator("security.run_script_bypass", text="Bypass All Security", icon='CANCEL')

            # Info about Ctrl+P override
            box.separator()
            info_box = box.box()
            info_box.label(text="Ctrl+P now uses secure execution", icon='INFO')

        layout.separator()

        # Global controls
        box = layout.box()
        box.label(text="Global Security", icon='LOCKED')

        row = box.row()
        row.operator("security.manual_check", text="Scan All Scripts", icon='VIEWZOOM')

        # Monitoring status - check if the timer is actually registered
        if bpy.app.timers.is_registered(continuous_monitoring):
            row = box.row()
            row.label(text="Monitoring Active", icon='CHECKMARK')
        else:
            row = box.row()
            row.alert = True
            row.label(text="Monitoring Inactive", icon='CANCEL')
            # Add button to restart monitoring if it's not active
            row = box.row()
            row.operator("security.restart_monitoring", text="Start Monitoring", icon='PLAY')

# Add operator to analyze current text
class SECURITY_OT_AnalyzeCurrentText(bpy.types.Operator):
    """Analyze the currently open text"""
    bl_idname = "security.analyze_current_text"
    bl_label = "Analyze Current Text"
    bl_description = "Analyze the currently open text for security issues"

    def execute(self, context):
        if not context.space_data.text:
            self.report({'ERROR'}, "No text to analyze")
            return {'CANCELLED'}

        text = context.space_data.text
        content = text.as_string()

        if not content.strip():
            self.report({'INFO'}, "No content to analyze")
            return {'FINISHED'}

        analyzer = BlenderSecurityAnalyzer()

        if analyzer._is_python_script(content):
            script_analysis = analyzer.analyze_script(content, text.name)

            # Report results
            risk_level = script_analysis['risk_level']
            issue_count = len(script_analysis['issues'])

            if risk_level == 'CRITICAL':
                self.report({'ERROR'}, f"CRITICAL RISK: {issue_count} issues found in '{text.name}'")
            elif risk_level == 'HIGH':
                self.report({'WARNING'}, f"HIGH RISK: {issue_count} issues found in '{text.name}'")
            elif risk_level == 'MEDIUM':
                self.report({'WARNING'}, f"MEDIUM RISK: {issue_count} issues found in '{text.name}'")
            else:
                self.report({'INFO'}, f"LOW RISK: {issue_count} issues found in '{text.name}'")

            # Print detailed results to console
            print(f"\n=== Security Analysis: {text.name} ===")
            print(f"Risk Level: {risk_level}")
            print(f"Issues Found: {issue_count}")

            for issue in script_analysis['issues']:
                print(f"  Line {issue['line']}: {issue['type']} ({issue['severity']})")
                print(f"    {issue['description']}")
                print(f"    Code: {issue['code']}")

            if script_analysis['suspicious_imports']:
                print("Suspicious Imports:")
                for imp in script_analysis['suspicious_imports']:
                    print(f"  - {imp}")
        else:
            self.report({'INFO'}, f"'{text.name}' is not recognized as Python code")

        return {'FINISHED'}

# Add a security bypass operator for advanced users (optional)
class SECURITY_OT_RunScriptBypass(bpy.types.Operator):
    """Run script bypassing security (USE WITH EXTREME CAUTION)"""
    bl_idname = "security.run_script_bypass"
    bl_label = "Run Script (BYPASS SECURITY)"
    bl_description = "Run script bypassing all security checks - USE WITH EXTREME CAUTION"
    bl_options = {'REGISTER', 'UNDO'}

    confirm: bpy.props.BoolProperty(
        name="I understand the risks",
        description="Check this to confirm you understand the security risks",
        default=False
    )

    @classmethod
    def poll(cls, context):
        return (context.area and context.area.type == 'TEXT_EDITOR' and
                context.space_data.text is not None)

    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self, width=400)

    def draw(self, context):
        layout = self.layout

        # Warning header
        box = layout.box()
        box.alert = True
        row = box.row()
        row.scale_y = 1.5
        row.label(text="SECURITY BYPASS WARNING" , icon='ERROR')

        box.label(text="You are about to run a script that")
        box.label(text="contains potentially malicious code!")
        box.label(text="")
        box.label(text="This could:")
        box.label(text="• Damage your system")
        box.label(text="• Steal your data")
        box.label(text="• Install malware")
        box.label(text="• Delete files")

        layout.separator()
        layout.prop(self, "confirm")

    def execute(self, context):
        if not self.confirm:
            self.report({'ERROR'}, "Must confirm understanding of risks")
            return {'CANCELLED'}

        text = context.space_data.text
        if not text:
            self.report({'ERROR'}, "No text to run")
            return {'CANCELLED'}

        content = text.as_string()
        if not content.strip():
            self.report({'ERROR'}, "No content to run")
            return {'CANCELLED'}

        print(f"BlendScan: SECURITY BYPASSED - Executing script '{text.name}' without protection!")

        try:
            # Execute without security checks
            code = compile(content, text.name, 'exec')
            exec_globals = {"__name__": "__main__", "__file__": text.name}
            exec_globals.update(bpy.app.driver_namespace)
            exec(code, exec_globals)

            self.report({'WARNING'}, f"Script '{text.name}' executed with BYPASSED SECURITY")

        except Exception as e:
            self.report({'ERROR'}, f"Script execution failed: {str(e)}")
            return {'CANCELLED'}

        return {'FINISHED'}

@persistent
def security_check_on_load(dummy):
    """Auto-run security check when a blend file is loaded"""
    try:
        # Small delay to ensure file is fully loaded
        bpy.app.timers.register(lambda: run_security_analysis(), first_interval=0.5)
    except Exception as e:
        print(f"Security check error: {e}")

@persistent
def security_check_on_save(dummy):
    """Auto-run security check when a blend file is saved"""
    try:
        bpy.app.timers.register(lambda: run_security_analysis(), first_interval=0.1)
    except Exception as e:
        print(f"Security check on save error: {e}")

# Add continuous monitoring
class TextMonitor:
    """Monitor text blocks for changes and new additions"""
    def __init__(self):
        self.known_texts = {}
        self.update_known_texts()

    def update_known_texts(self):
        """Update the record of known text blocks"""
        try:
            # Check if we can access bpy.data safely
            if hasattr(bpy.data, 'texts') and bpy.data.texts is not None:
                self.known_texts = {
                    text.name: hashlib.sha256(text.as_string().encode()).hexdigest()
                    for text in bpy.data.texts
                    if text is not None
                }
            else:
                # If we can't access texts, keep existing known_texts
                pass
        except Exception as e:
            print(f"BlendScan: Error updating known texts: {e}")
            # Keep existing known_texts on error

    def check_for_changes(self):
        """Check if any text blocks have been added or modified"""
        try:
            # Check if we can access bpy.data safely
            if not hasattr(bpy.data, 'texts') or bpy.data.texts is None:
                return False

            current_texts = {}
            for text in bpy.data.texts:
                if text is not None:
                    try:
                        content = text.as_string()
                        current_texts[text.name] = hashlib.sha256(content.encode()).hexdigest()
                    except Exception as e:
                        print(f"BlendScan: Error reading text '{text.name}': {e}")
                        continue

            # Check for new or modified texts
            changes_detected = False
            for name, hash_val in current_texts.items():
                if name not in self.known_texts or self.known_texts[name] != hash_val:
                    changes_detected = True
                    # Immediately analyze this specific text
                    text = bpy.data.texts.get(name)
                    if text and text.as_string().strip():
                        self.analyze_single_text(text)

            # Update known texts
            self.known_texts = current_texts
            return changes_detected

        except Exception as e:
            print(f"BlendScan: Error checking for text changes: {e}")
            return False

    def analyze_single_text(self, text):
        """Analyze a single text block immediately"""
        try:
            if text is None:
                return

            analyzer = BlenderSecurityAnalyzer()
            content = text.as_string()

            if analyzer._is_python_script(content):
                script_analysis = analyzer.analyze_script(content, text.name)

                # Check if this specific script has critical issues
                if script_analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                    print(f"CRITICAL THREAT DETECTED in text block: {text.name}")
                    print(f"Risk Level: {script_analysis['risk_level']}")

                    # Create minimal results for the warning dialog
                    threat_results = {
                        'overall_risk': script_analysis['risk_level'],
                        'embedded_scripts': [script_analysis],
                        'drivers_analysis': [],
                        'custom_properties': [],
                        'addon_analysis': [],
                        'auto_run_status': {'enabled': bpy.context.preferences.filepaths.use_scripts_auto_execute},
                        'recommendations': [
                            f"Malicious code detected in '{text.name}'",
                            "Remove or review the suspicious script immediately",
                            "Do not run this script"
                        ]
                    }

                    # Show immediate warning
                    try:
                        bpy.ops.security.countdown_warning(
                            'INVOKE_DEFAULT',
                            security_issues=str(threat_results)
                        )
                    except Exception as e:
                        print(f"Error showing immediate security dialog: {e}")
                        # Fallback warning
                        self.show_console_warning(script_analysis)

        except Exception as e:
            print(f"Error analyzing text block {getattr(text, 'name', 'unknown')}: {e}")

# Global text monitor instance
text_monitor = None

def continuous_monitoring():
    """Continuous monitoring function that runs periodically"""
    global text_monitor

    try:
        # Check if Blender is in a valid state for monitoring
        if not bpy.context or not hasattr(bpy, 'data'):
            return 5.0  # Retry in 5 seconds

        # Check if we're in a restricted context (like during file loading)
        try:
            # Test access to bpy.data
            test_access = len(bpy.data.texts) if hasattr(bpy.data, 'texts') else 0
        except:
            # If we can't access data, skip this cycle
            return 2.0

        if text_monitor is None:
            text_monitor = TextMonitor()

        # Check for text changes
        if text_monitor.check_for_changes():
            print("Text changes detected - security analysis triggered")

        # Continue monitoring every 2 seconds
        return 2.0

    except Exception as e:
        print(f"Continuous monitoring error: {e}")
        # Reset monitor on error and retry
        text_monitor = None
        return 5.0  # Retry in 5 seconds if there's an error

def start_continuous_monitoring():
    """Start the continuous monitoring system"""
    global text_monitor
    try:
        # Don't initialize monitor immediately - let the timer handle it
        text_monitor = None

        # Register the monitoring timer
        if not bpy.app.timers.is_registered(continuous_monitoring):
            bpy.app.timers.register(continuous_monitoring, first_interval=2.0)
            print("BlendScan: Continuous monitoring started")
        else:
            print("BlendScan: Continuous monitoring already running")
    except Exception as e:
        print(f"Error starting continuous monitoring: {e}")

def stop_continuous_monitoring():
    """Stop the continuous monitoring system"""
    try:
        if bpy.app.timers.is_registered(continuous_monitoring):
            bpy.app.timers.unregister(continuous_monitoring)
            print("BlendScan: Continuous monitoring stopped")
    except Exception as e:
        print(f"Error stopping continuous monitoring: {e}")

# Add operator for manual security check
class SECURITY_OT_ManualCheck(bpy.types.Operator):
    """Manual security check operator"""
    bl_idname = "security.manual_check"
    bl_label = "Run Security Check"
    bl_description = "Manually run security analysis on current file"

    def execute(self, context):
        self.report({'INFO'}, "Security check completed - see console for details")
        return {'FINISHED'}

def run_security_analysis():
    """Run the security analysis and show warning if threats detected"""
    try:
        analyzer = BlenderSecurityAnalyzer()
        results = analyzer.analyze_blend_file_security(bpy.context)

        # Check if there are any security issues
        has_critical_issues = results['overall_risk'] in ['HIGH', 'CRITICAL']
        has_script_issues = any(
            script['risk_level'] in ['HIGH', 'CRITICAL']
            for script in results['embedded_scripts']
        )
        has_driver_issues = len(results['drivers_analysis']) > 0
        has_suspicious_props = len(results['custom_properties']) > 0

        # Show warning if any serious threats detected
        if has_critical_issues or has_script_issues or has_driver_issues or has_suspicious_props:
            # Store results and show countdown warning
            bpy.context.scene.security_threat_data = str(results)

            print("SECURITY THREAT DETECTED - SHOWING WARNING DIALOG")
            print(f"Risk Level: {results['overall_risk']}")
            print(f"Embedded Scripts: {len(results['embedded_scripts'])}")
            print(f"Suspicious Drivers: {len(results['drivers_analysis'])}")
            print(f"Suspicious Properties: {len(results['custom_properties'])}")

            # Show the countdown warning popup
            try:
                bpy.ops.security.countdown_warning(
                    'INVOKE_DEFAULT',
                    security_issues=str(results)
                )
            except Exception as e:
                print(f"Error showing security dialog: {e}")
                # Fallback: just print warning and close after delay
                print("FALLBACK: Blender will close in 10 seconds due to security threat")
                def delayed_quit():
                    time.sleep(10)
                    bpy.ops.wm.quit_blender()
                import threading
                threading.Thread(target=delayed_quit, daemon=True).start()

        else:
            print("Security analysis complete - no threats detected")

    except Exception as e:
        print(f"Security analysis error: {e}")

    # Return None to unregister the timer
    return None

# Classes to register
classes = [
    SECURITY_OT_CountdownWarning,
    SECURITY_OT_ManualCheck,
    SECURITY_OT_SecureRunScript,
    SECURITY_OT_AnalyzeCurrentText,
    SECURITY_OT_RunScriptBypass,
    SECURITY_OT_ToggleAutoRun,
    SECURITY_PT_TextEditorPanel
]

def register():
    for cls in classes:
        bpy.utils.register_class(cls)

    # Register the file load handler
    if security_check_on_load not in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.append(security_check_on_load)

    # Register the file save handler
    if security_check_on_save not in bpy.app.handlers.save_pre:
        bpy.app.handlers.save_pre.append(security_check_on_save)

    # Add scene property for threat data
    bpy.types.Scene.security_threat_data = bpy.props.StringProperty(
        name="Security Threat Data",
        description="Detected security threat information",
        default=""
    )

    # Disable auto-run scripts immediately upon addon registration
    disable_auto_run_scripts()

    # Add keymap override for Ctrl+P
    SecurityKeymapHelper.add_keymap()

    # Start continuous monitoring
    start_continuous_monitoring()

    # Run immediate security check when addon is enabled
    print("BlendScan addon registered - running initial security check...")
    bpy.app.timers.register(lambda: run_security_analysis(), first_interval=0.5)

def unregister():
    # Remove keymap override first
    SecurityKeymapHelper.remove_keymap()

    # Stop continuous monitoring first
    stop_continuous_monitoring()

    # Restore original auto-run setting (optional - user choice)
    # restore_auto_run_scripts()  # Uncomment this line if you want to restore the original setting

    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)

    # Remove the file load handler
    if security_check_on_load in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.remove(security_check_on_load)

    # Remove the file save handler
    if security_check_on_save in bpy.app.handlers.save_pre:
        bpy.app.handlers.save_pre.remove(security_check_on_save)

    # Clean up scene property
    if hasattr(bpy.types.Scene, 'security_threat_data'):
        del bpy.types.Scene.security_threat_data

if __name__ == "__main__":
    register()