"""
Support and troubleshooting tools for WinDbg MCP server.

This module contains tools for troubleshooting issues and getting help.
"""
import logging
from typing import Dict, Any, List, Optional, Union
from fastmcp import FastMCP, Context

from core.communication import send_command, test_connection, test_target_connection
from core.error_handler import enhance_error, error_enhancer, DebugContext
from core.hints import get_parameter_help
# _get_timeout moved to unified execution system

logger = logging.getLogger(__name__)

def _get_timeout(command: str) -> int:
    """Helper function to get timeout for commands using unified system."""
    from core.execution.timeout_resolver import resolve_timeout
    from config import DebuggingMode
    return resolve_timeout(command, DebuggingMode.VM_NETWORK)

def register_support_tools(mcp: FastMCP):
    """Register all support and troubleshooting tools."""
    
    @mcp.tool()
    async def troubleshoot(ctx: Context, action: str) -> Union[str, Dict[str, Any]]:
        """
        Troubleshoot common debugging issues.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "symbols", "exception", "analyze", "connection"
            
        Returns:
            Troubleshooting results and recommendations
        """
        logger.debug(f"Troubleshooting action: {action}")
        
        try:
            if action == "symbols":
                # Symbol troubleshooting
                results = ["=== SYMBOL TROUBLESHOOTING ==="]
                
                try:
                    # Check symbol path
                    sympath = send_command(".sympath", timeout_ms=_get_timeout(".sympath"))
                    results.append(f"Symbol path: {sympath}")
                    
                    # Check specific modules
                    modules = ["nt", "ntdll", "kernel32"]
                    for module in modules:
                        try:
                            module_info = send_command(f"lmv m {module}", timeout_ms=_get_timeout(f"lmv m {module}"))
                            results.append(f"\n{module} module:\n{module_info}")
                        except:
                            results.append(f"\n{module} module: Not found")
                    
                    # Try symbol reload
                    results.append("\nAttempting symbol reload...")
                    reload_result = send_command(".reload", timeout_ms=_get_timeout(".reload"))
                    results.append(reload_result)
                    
                    return "\n".join(results)
                except Exception as e:
                    return f"Symbol troubleshooting failed: {str(e)}"
                
            elif action == "exception":
                # Full driver crash / bugcheck analysis workflow.
                # Runs the same sequence as analyze_kernel(action='bugcheck') but is
                # accessible from the troubleshoot tool for convenience.
                crash_steps = []

                # 1. Bugcheck code and raw parameters
                try:
                    bc_out = send_command(".bugcheck", timeout_ms=_get_timeout(".bugcheck"))
                    crash_steps.append({"step": "bugcheck_info", "output": bc_out, "success": True})
                except Exception as e:
                    crash_steps.append({"step": "bugcheck_info", "error": str(e), "success": False})

                # 2. Full crash analysis (no -hang flag — that is for freezes only)
                try:
                    analyze_out = send_command("!analyze -v", timeout_ms=_get_timeout("!analyze -v"))
                    crash_steps.append({"step": "crash_analysis", "output": analyze_out, "success": True})
                except Exception as e:
                    crash_steps.append({"step": "crash_analysis", "error": str(e), "success": False})

                # 3. Call stack of the crashing thread
                try:
                    stack_out = send_command("kP 30", timeout_ms=_get_timeout("kP"))
                    crash_steps.append({"step": "crash_stack", "output": stack_out, "success": True})
                except Exception as e:
                    crash_steps.append({"step": "crash_stack", "error": str(e), "success": False})

                return {
                    "context": "Driver crash / exception analysis",
                    "steps": crash_steps,
                    "next_steps": [
                        "Find 'MODULE_NAME' and 'IMAGE_NAME' in crash_analysis — that is the responsible driver",
                        "Find 'STACK_TEXT' in crash_analysis to trace the exact failure path",
                        "Use 'lm a <address>' to identify any unknown address as a module",
                        "If pool corruption (0xC2/0x19): run run_command('!pool <param2_addr>')",
                        "If IRQL violation (0xD1/0x0A): driver is accessing paged memory at high IRQL",
                        "For symbols: troubleshoot(action='symbols') if MODULE_NAME shows '???'"
                    ]
                }

            elif action == "analyze":
                # General system analysis — same as exception but kept for backward compat.
                # Prefer troubleshoot(action='exception') for crash, analyze_kernel(action='analyze')
                # for hangs.
                result = send_command("!analyze -v", timeout_ms=_get_timeout("!analyze -v"))
                return {
                    "context": "General system analysis (!analyze -v)",
                    "output": result,
                    "tip": (
                        "For a full crash workflow use troubleshoot(action='exception'). "
                        "For hang analysis use analyze_kernel(action='analyze')."
                    )
                }
            
            elif action == "connection":
                # Test connection and provide status
                connected = test_connection()
                if connected:
                    version = send_command("version", timeout_ms=_get_timeout("version"))
                    return f"✓ Connection OK\n\nWinDbg Version:\n{version}"
                else:
                    return "✗ Connection Failed\n\nEnsure:\n1. WinDbg extension is loaded\n2. Extension DLL is correct version\n3. Named pipe is available"
            
            else:
                return {"error": f"Unknown action: {action}. Use 'symbols', 'exception', 'analyze', or 'connection'"}
                
        except Exception as e:
            logger.error(f"Error in troubleshoot: {e}")
            return {"error": str(e)}

    @mcp.tool()
    async def get_help(ctx: Context, tool_name: str = "", action: str = "") -> Dict[str, Any]:
        """
        Get help, examples, and parameter information for MCP tools.
        
        Args:
            ctx: The MCP context
            tool_name: Name of the tool to get help for (empty for list of all tools)
            action: Specific action to get help for (empty for all actions)
            
        Returns:
            Help information, examples, and parameter details
        """
        logger.debug(f"Getting help for tool: {tool_name}, action: {action}")
        
        if not tool_name:
            # List all available tools
            available_tools = [
                "debug_session", "run_command", "run_sequence", "breakpoint_and_continue",
                "analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel",
                "connection_manager", "session_manager", 
                "performance_manager", "async_manager",
                "troubleshoot", "get_help"
            ]
            
            return {
                "available_tools": available_tools,
                "description": "WinDbg MCP Server - Debugging with LLM Automation",
                "usage": "Use get_help(tool_name='tool_name') to get help for a specific tool",
                "examples": [
                    "get_help(tool_name='analyze_process')",
                    "get_help(tool_name='run_command')",
                    "get_help(tool_name='breakpoint_and_continue')",
                    "get_help(tool_name='analyze_process', action='switch')"
                ],
                "tool_categories": {
                    "session_management": ["debug_session", "connection_manager", "session_manager"],
                    "command_execution": ["run_command", "run_sequence", "breakpoint_and_continue"],
                    "analysis": ["analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel"],
                    "performance": ["performance_manager", "async_manager"],
                    "support": ["troubleshoot", "get_help"]
                },
                "automation_features": {
                    "execution_control": "✅ Now enabled for LLM automation (g, p, t, gu, wt)",
                    "breakpoint_control": "✅ Now enabled for LLM automation (bp, bc, bd, be, etc.)",
                    "context_switching": "✅ Now enabled for LLM automation (.thread, .process)",
                    "combined_operations": "✅ Use breakpoint_and_continue for one-step breakpoint + execution"
                },
                "tip": "All tools provide error messages with suggestions and examples when something goes wrong"
            }
        
        # Get help for specific tool - Fixed parameter validation
        try:
            help_info = get_parameter_help(tool_name, action)
        except Exception as e:
            logger.debug(f"Error getting parameter help for {tool_name}: {e}")
            help_info = None
        
        if not help_info:
            return {
                "error": f"Tool '{tool_name}' not found or no help available",
                "error_code": "tool_not_found", 
                "available_tools": [
                    "debug_session", "run_command", "run_sequence", "breakpoint_and_continue",
                    "analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel",
                    "connection_manager", "session_manager",
                    "performance_manager", "async_manager", 
                    "troubleshoot", "get_help"
                ],
                "suggestion": f"Use get_help() without parameters to see all available tools"
            }
        
        # Add debugging context information
        current_context = error_enhancer.current_context
        context_info = {
            "current_debugging_context": current_context.value,
            "context_specific_notes": []
        }
        
        if current_context == DebugContext.KERNEL_MODE:
            context_info["context_specific_notes"].append("You are in kernel-mode debugging - some user-mode tools (like PEB/TEB) won't work")
        elif current_context == DebugContext.USER_MODE:
            context_info["context_specific_notes"].append("You are in user-mode debugging - kernel-specific tools may have limited functionality")
        
        help_info["context"] = context_info
        
        # Add tool-specific tips based on the tool name
        if tool_name == "run_command":
            help_info["performance_tips"] = [
                "Use resilient=True (default) for unstable VM connections",
                "Use optimize=True (default) for better caching and performance", 
                "Commands are automatically categorized for optimal timeouts"
            ]
            help_info["execution_control_tips"] = [
                "✅ Execution control commands now enabled for LLM automation:",
                "  • 'g' - Continue execution",
                "  • 'p' - Step over (execute one instruction)",
                "  • 't' - Step into (trace one instruction)",
                "  • 'gu' - Go up (execute until function return)",
                "  • 'wt' - Watch and trace execution",
                "✅ Breakpoint commands now enabled for LLM automation:",
                "  • 'bp <address>' - Set breakpoint",
                "  • 'bc <id>' - Clear breakpoint",
                "  • 'bd <id>' - Disable breakpoint",
                "  • 'be <id>' - Enable breakpoint",
                "💡 Use breakpoint_and_continue() for combined operations"
            ]
        elif tool_name == "breakpoint_and_continue":
            help_info["usage_examples"] = [
                "breakpoint_and_continue(breakpoint='nt!NtCreateFile')",
                "breakpoint_and_continue(breakpoint='kernel32!CreateFileW', continue_execution=True)",
                "breakpoint_and_continue(breakpoint='0x12345678', clear_existing=True)",
                "breakpoint_and_continue(breakpoint='ntdll!NtOpenFile', continue_execution=False)"
            ]
            help_info["automation_benefits"] = [
                "🚀 Combines breakpoint setting + execution control in one operation",
                "🎯 Designed for LLM debugging workflows",
                "🔄 Automatic context saving and error recovery",
                "📊 Detailed step-by-step execution reporting",
                "💡 Built-in guidance for next debugging steps"
            ]
        elif tool_name in ["analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel"]:
            help_info["analysis_tips"] = [
                "Use save_context=True (default) when switching contexts",
                "Tools automatically detect kernel vs user mode",
                "Error messages guide you when operations fail"
            ]
        elif tool_name in ["performance_manager", "async_manager"]:
            help_info["performance_tips"] = [
                "Set optimization level to 'aggressive' for VM debugging",
                "Use async execution for multiple independent commands",
                "Monitor performance reports to optimize your workflow"
            ]
        
        return help_info 

    @mcp.tool()
    async def test_windbg_communication() -> str:
        """
        Test communication with WinDbg extension and provide detailed results.
        
        This tool specifically tests the named pipe communication between
        the Python MCP server and the WinDbg extension.
        
        Returns:
            Communication test results and recommendations
        """
        try:
            from core.communication import (
                test_connection, test_target_connection, send_command,
                NetworkDebuggingError
            )
            
            results = ["🧪 WINDBG COMMUNICATION TEST", "=" * 40, ""]
            
            # Test 1: Basic extension connection
            try:
                connected = test_connection()
                if connected:
                    results.append("✅ Test 1: Extension connection - PASSED")
                else:
                    results.append("❌ Test 1: Extension connection - FAILED")
            except Exception as e:
                results.append(f"❌ Test 1: Extension connection - ERROR: {e}")
            
            results.append("")
            
            # Test 2: Test target connection
            try:
                is_connected, status = test_target_connection()
                if is_connected:
                    results.append("✅ Test 2: Target connection - PASSED (Kernel debugging target connected)")
                else:
                    results.append(f"❌ Test 2: Target connection - FAILED ({status})")
            except Exception as e:
                results.append(f"❌ Test 2: Target connection - ERROR: {e}")
            
            results.append("")
            
            # Test 3: Basic command execution
            try:
                result = send_command("version", timeout_ms=_get_timeout("version"))
                if result and "Windows" in result:
                    results.append("✅ Test 3: Command execution - PASSED")
                    results.append(f"    Response: {result[:100]}...")
                else:
                    results.append("❌ Test 3: Command execution - FAILED (No response)")
            except Exception as e:
                results.append(f"❌ Test 3: Command execution - ERROR: {e}")
            
            results.append("")
            results.append("📊 Summary:")
            results.append("  • Communication tests completed")
            results.append("  • Check individual test results above for details")
            
            return "\n".join(results)
            
        except Exception as e:
            logger.error(f"Communication test failed: {e}")
            return f"❌ Communication test failed: {str(e)}"

    @mcp.tool()
    async def network_debugging_troubleshoot() -> str:
        """
        Specialized troubleshooting for network debugging connection issues.
        
        This tool provides specific guidance for VM-based kernel debugging
        scenarios where packet loss and connection instability are common.
        
        Returns:
            Network debugging troubleshooting guide and status
        """
        try:
            from core.communication import (
                test_connection, test_target_connection, send_command,
                NetworkDebuggingError
            )
            
            results = ["🌐 NETWORK DEBUGGING TROUBLESHOOT", "=" * 42, ""]
            
            # Test 1: Basic connectivity
            try:
                connected = test_connection()
                if connected:
                    results.append("✅ Extension connection - OK")
                else:
                    results.append("❌ Extension connection - FAILED")
                    results.append("   → Load extension: .load C:\\path\\to\\windbgmcpExt.dll")
                    results.append("")
            except Exception as e:
                results.append(f"❌ Extension connection error: {e}")
            
            # Test 2: Target connectivity with network considerations
            try:
                is_connected, status = test_target_connection()
                if is_connected:
                    results.append("✅ Target connection - OK")
                    
                    # Get additional network debugging info
                    result = send_command("version", timeout_ms=_get_timeout("version"))
                    if "Remote KD" in result:
                        results.append("   → Network kernel debugging detected")
                        if "Trans=@{NET:" in result:
                            results.append("   → Using network transport (optimal)")
                        else:
                            results.append("   → Check network transport configuration")
                else:
                    results.append(f"❌ Target connection - FAILED: {status}")
                    results.append("   → Check VM network debugging configuration")
                    results.append("   → Verify bcdedit settings on target VM")
                    
            except Exception as e:
                results.append(f"❌ Target connection error: {e}")
            
            results.append("")
            results.append("🔧 NETWORK DEBUGGING TIPS:")
            results.append("   • Increase timeouts for unstable connections")
            results.append("   • Use resilient execution mode (enabled by default)")
            results.append("   • Monitor packet loss with network tools")
            results.append("   • Consider increasing VM network adapter buffer sizes")
            results.append("")
            results.append("📋 Quick Commands:")
            results.append("   • Run 'vertarget' in WinDbg command window")
            results.append("   • Check '.kdfiles' for symbol loading over network")
            results.append("   • Use '!vm' to check target memory accessibility")
            
            return "\n".join(results)
            
        except Exception as e:
            logger.error(f"Network troubleshooting failed: {e}")
            return f"❌ Network troubleshooting failed: {str(e)}" 
