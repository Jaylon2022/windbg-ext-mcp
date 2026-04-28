"""
Analysis tools for WinDbg MCP server.

This module contains tools for analyzing processes, threads, memory, and kernel objects.
"""
import logging
import re
import time
from typing import Dict, Any, List, Optional, Union
from fastmcp import FastMCP, Context

from core.communication import send_command, TimeoutError, CommunicationError
from core.context import get_context_manager
from core.error_handler import enhance_error, error_enhancer, DebugContext, ErrorCategory
from core.hints import get_parameter_help, validate_tool_parameters
from .tool_utilities import detect_kernel_mode

logger = logging.getLogger(__name__)

def _get_timeout(command: str) -> int:
    """Helper function to get timeout for commands using unified system."""
    from core.execution.timeout_resolver import resolve_timeout
    from config import DebuggingMode
    return resolve_timeout(command, DebuggingMode.VM_NETWORK)


def register_analysis_tools(mcp: FastMCP):
    """Register all analysis tools."""
    
    @mcp.tool()
    async def analyze_process(ctx: Context, action: str, address: str = "", save_context: bool = True) -> Union[str, Dict[str, Any]]:
        """
        Analyze processes in the debugging session.

        In kernel-mode debugging, the normal workflow to inspect a user-space process
        (e.g. dwm.exe) is:
          1. action='list'   - run !process 0 0 to find the target EPROCESS address
          2. action='switch' - switch virtual address space with .process /r /p <addr>
                               (non-invasive; no need to continue the target)
          3. action='threads'- list all ETHREAD objects for the process (!process <addr> 4)
          4. Use analyze_thread(action='stack', address=<ETHREAD addr>) for each thread
          5. action='restore'- return to original kernel context

        Args:
            ctx: The MCP context
            action: Action to perform:
                    "list"    - enumerate all processes (!process 0 0)
                    "switch"  - switch process context (.process /r /p in kernel,
                                .process /i in user/invasive mode when needed)
                    "threads" - list threads of a process (!process <addr> 4)
                    "info"    - detailed process dump (!process <addr> 7)
                    "peb"     - user-mode PEB (user-mode only)
                    "restore" - restore previously saved context
            address: Process EPROCESS address (required for switch/threads/info/peb)
            save_context: Whether to save current context before switching (default: True)

        Returns:
            Process analysis results
        """
        logger.debug(f"Analyze process action: {action}, address: {address}")
        
        # Parameter validation
        params = {"action": action}
        if address:
            params["address"] = address
        if save_context is not True:  # Only include if not default
            params["save_context"] = save_context

        _valid_actions = ["list", "switch", "threads", "info", "peb", "restore"]
        is_valid, validation_errors = validate_tool_parameters("analyze_process", action, params)
        if not is_valid:
            if action not in _valid_actions:
                # Invalid action
                help_info = get_parameter_help("analyze_process")
                enhanced_error = enhance_error("parameter", 
                                             tool_name="analyze_process", 
                                             action="", 
                                             missing_param="action")
                error_dict = enhanced_error.to_dict()
                error_dict["available_actions"] = list(help_info.get("actions", {}).keys())
                error_dict["help"] = help_info.get("actions", {}).get(action, {})
                return error_dict
            else:
                # Missing required parameter (likely address)
                enhanced_error = enhance_error("parameter", 
                                             tool_name="analyze_process", 
                                             action=action, 
                                             missing_param="address")
                return enhanced_error.to_dict()
        
        try:
            context_mgr = get_context_manager()
            
            if action == "list":
                # List all processes
                try:
                    result = send_command("!process 0 0", timeout_ms=_get_timeout("!process 0 0"))
                    
                    return {
                        "output": result,
                        "next_steps": [
                            "Copy process address from output for other actions",
                            "Use analyze_process(action='info', address='...') for details", 
                            "Switch context with analyze_process(action='switch', address='...')"
                        ],
                        "tip": "Copy a process address from the output above to use with other actions"
                    }
                    
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command="!process 0 0", timeout_ms=_get_timeout("!process 0 0"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!process 0 0", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "switch":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_process", missing_param="address")
                    return enhanced_error.to_dict()
                    
                # Save current context if requested
                if save_context:
                    saved = context_mgr.push_context(send_command)
                    logger.debug(f"Saved context before process switch")

                is_kernel = detect_kernel_mode()
                try:
                    if is_kernel:
                        # Non-invasive virtual address space switch — works immediately
                        # without needing to continue/break the target again.
                        # /r reloads user-mode symbols for the new process.
                        # /p sets the implicit process (affects dt, !peb, etc.).
                        switch_cmd = f".process /r /p {address}"
                        result = send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                        return {
                            "success": True,
                            "output": result,
                            "switched_to": address,
                            "mode": "kernel_non_invasive",
                            "next_steps": [
                                "Context switched — you can now inspect this process's virtual memory",
                                "Use analyze_process(action='threads', address=...) to list its threads",
                                "Use analyze_thread(action='stack', address=<ETHREAD>) to see a thread's stack",
                                "Use analyze_process(action='restore') when done"
                            ]
                        }
                    else:
                        # Invasive switch for user-mode debugging
                        switch_cmd = f".process /i {address}"
                        result = send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                        return {
                            "success": True,
                            "output": result,
                            "switched_to": address,
                            "mode": "user_invasive",
                            "next_steps": [
                                "Run 'g' to let the target reach a breakpoint in this process context",
                                "After breaking, inspect threads, memory, etc."
                            ]
                        }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=switch_cmd, original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "threads":
                # List all threads belonging to a specific process.
                # This uses !process <addr> 4 which outputs ETHREAD addresses — the
                # correct input for analyze_thread(action='switch'/'stack') in kernel mode.
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_process", missing_param="address")
                    return enhanced_error.to_dict()
                try:
                    result = send_command(f"!process {address} 4", timeout_ms=_get_timeout(f"!process {address} 4"))
                    # Parse out ETHREAD addresses to guide the AI
                    thread_addrs = re.findall(r'THREAD\s+([0-9a-fA-F`]+)', result)
                    return {
                        "output": result,
                        "process_address": address,
                        "thread_addresses": thread_addrs,
                        "thread_count": len(thread_addrs),
                        "next_steps": [
                            f"To see a thread's call stack: analyze_thread(action='stack', address='<ETHREAD addr>')",
                            f"To see thread details: analyze_thread(action='info', address='<ETHREAD addr>')",
                            "ETHREAD addresses are listed in thread_addresses above"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!process {address} 4", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "info":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_process", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Get detailed process information
                    result = send_command(f"!process {address} 7", timeout_ms=_get_timeout(f"!process {address} 7"))
                    return {"output": result, "process_address": address}
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command=f"!process {address} 7", timeout_ms=_get_timeout(f"!process {address} 7"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!process {address} 7", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "peb":
                # Get Process Environment Block information
                if detect_kernel_mode():
                    return {
                        "error": "PEB analysis not available in kernel mode",
                        "suggestion": "Use !process command for kernel-mode process analysis",
                        "category": "mode_mismatch"
                    }
                
                try:
                    if address:
                        # Switch to process first, then get PEB
                        switch_cmd = f".process /i {address}"
                        send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                        
                    peb_result = send_command("!peb", timeout_ms=_get_timeout("!peb"))
                    return {"output": peb_result, "context": "Process Environment Block"}
                    
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command="!peb", timeout_ms=_get_timeout("!peb"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!peb", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "restore":
                try:
                    success = context_mgr.pop_context(send_command)
                    if not success:
                        return {"success": False, "message": "No saved context to restore"}

                    error_enhancer.update_context(DebugContext.UNKNOWN)  # Reset context

                    # Use mode-appropriate command to confirm the restored context.
                    # !peb is a user-mode only command and fails in kernel debugging.
                    if detect_kernel_mode():
                        verify_cmd = "!pcr"
                    else:
                        verify_cmd = "!peb"

                    try:
                        result = send_command(verify_cmd, timeout_ms=_get_timeout(verify_cmd))
                        return {"success": True, "message": "Context restored", "current_context": result[:200]}
                    except Exception:
                        # Verification failure is non-fatal; the context was already restored
                        return {"success": True, "message": "Context restored (verification unavailable)"}

                except Exception as e:
                    enhanced_error = enhance_error("execution", command="restore", original_error=str(e))
                    return enhanced_error.to_dict()
            
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["list", "switch", "threads", "info", "peb", "restore"],
                    "kernel_workflow": [
                        "1. analyze_process(action='list') — find EPROCESS address of target",
                        "2. analyze_process(action='switch', address='<EPROCESS>') — switch VA space",
                        "3. analyze_process(action='threads', address='<EPROCESS>') — list ETHREAD addrs",
                        "4. analyze_thread(action='stack', address='<ETHREAD>') — get call stack",
                        "5. analyze_process(action='restore') — return to kernel context"
                    ],
                    "examples": [
                        "analyze_process(action='list')",
                        "analyze_process(action='switch', address='0xffff8e0e481d7080')",
                        "analyze_process(action='threads', address='0xffff8e0e481d7080')",
                        "analyze_process(action='info', address='0xffff8e0e481d7080')"
                    ]
                }

        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_process", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_thread(ctx: Context, action: str, address: str = "", count: int = 20, process_address: str = "") -> Union[str, Dict[str, Any]]:
        """
        Analyze threads in the debugging session.

        In kernel-mode debugging:
          - 'address' is an ETHREAD pointer (obtained from analyze_process threads action
            or from !process <eprocess> 4 output).
          - Use action='switch' to set the implicit thread (.thread <ETHREAD>).
          - Use action='stack' to dump the kernel call stack of a specific thread
            (optionally supply process_address to first switch the VA space so user-mode
            frames are also resolved correctly).

        Args:
            ctx: The MCP context
            action: Action to perform:
                    "list"       - list threads (kernel: !process -1 6; user: ~*)
                    "switch"     - switch to thread context (kernel: .thread; user: ~ns)
                    "info"       - detailed thread dump (!thread <addr>)
                    "stack"      - call stack of a thread (kP or k)
                    "all_stacks" - stacks of all threads in current process
                    "teb"        - Thread Environment Block (user-mode only)
            address: ETHREAD address (kernel) or thread index (user)
            count: Number of stack frames to display (default: 20)
            process_address: (kernel only) EPROCESS of the owning process — when provided,
                             the VA space is switched first so user-mode symbols resolve
        
        Returns:
            Thread analysis results
        """
        logger.debug(f"Analyze thread action: {action}, address: {address}")
        
        is_kernel = detect_kernel_mode()

        try:
            context_mgr = get_context_manager()

            if action == "list":
                try:
                    if is_kernel:
                        # !process -1 6  → threads of current implicit process with basic info
                        result = send_command("!process -1 6", timeout_ms=_get_timeout("!process -1 6"))
                        thread_addrs = re.findall(r'THREAD\s+([0-9a-fA-F`]+)', result)
                        return {
                            "output": result,
                            "thread_addresses": thread_addrs,
                            "thread_count": len(thread_addrs),
                            "note": "Use the ETHREAD addresses above with action='stack' or action='info'"
                        }
                    else:
                        result = send_command("~*", timeout_ms=_get_timeout("~*"))
                        return {"output": result, "note": "Copy thread index for detailed analysis"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!process -1 6" if is_kernel else "~*", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "switch":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_thread", missing_param="address")
                    return enhanced_error.to_dict()

                try:
                    if is_kernel:
                        # address is an ETHREAD pointer
                        switch_cmd = f".thread {address}"
                    else:
                        # address is a thread index
                        switch_cmd = f"~{address}s"
                    result = send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                    return {
                        "output": result,
                        "switched_to": address,
                        "next_steps": ["Run analyze_thread(action='stack') to see the call stack"]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=switch_cmd, original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "info":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_thread", missing_param="address")
                    return enhanced_error.to_dict()

                try:
                    result = send_command(f"!thread {address}", timeout_ms=_get_timeout(f"!thread {address}"))
                    return {"output": result, "thread_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!thread {address}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "stack":
                try:
                    ops = []
                    if is_kernel:
                        # Kernel mode: first switch VA space if a process is given,
                        # then set implicit thread, then dump stack.
                        if process_address:
                            proc_cmd = f".process /r /p {process_address}"
                            send_command(proc_cmd, timeout_ms=_get_timeout(proc_cmd))
                            ops.append(proc_cmd)
                        if address:
                            thread_cmd = f".thread {address}"
                            send_command(thread_cmd, timeout_ms=_get_timeout(thread_cmd))
                            ops.append(thread_cmd)
                        # kP shows parameters; fall back to k if kP is too heavy
                        stack_result = send_command(f"kP {count}", timeout_ms=_get_timeout(f"kP {count}"))
                    else:
                        if address:
                            switch_cmd = f"~{address}s"
                            send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                            ops.append(switch_cmd)
                        stack_result = send_command(f"k {count}", timeout_ms=_get_timeout(f"k {count}"))
                    return {
                        "output": stack_result,
                        "thread_address": address,
                        "stack_frames": count,
                        "ops_performed": ops
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"k {count}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "all_stacks":
                try:
                    if is_kernel:
                        # !process -1 6 gives threads; iterate via !stacks or dump manually
                        proc_info = send_command("!process -1 6", timeout_ms=_get_timeout("!process -1 6"))
                        thread_addrs = re.findall(r'THREAD\s+([0-9a-fA-F`]+)', proc_info)
                        stacks = []
                        for taddr in thread_addrs[:min(len(thread_addrs), 8)]:
                            try:
                                send_command(f".thread {taddr}", timeout_ms=_get_timeout(".thread"))
                                stack = send_command(f"k {min(count, 15)}", timeout_ms=_get_timeout("k"))
                                stacks.append({"thread": taddr, "stack": stack})
                            except Exception:
                                stacks.append({"thread": taddr, "stack": "(failed to get stack)"})
                        return {
                            "thread_count": len(thread_addrs),
                            "stacks_shown": len(stacks),
                            "stacks": stacks,
                            "note": "Only first 8 threads shown. Use action='stack' with a specific address for others."
                        }
                    else:
                        # User mode: ~*k
                        result = send_command(f"~*k {count}", timeout_ms=_get_timeout(f"~*k {count}"))
                        return {"output": result, "stack_frames": count}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="all_stacks", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "teb":
                if is_kernel:
                    return {
                        "error": "TEB is a user-mode structure and is not directly accessible in kernel mode",
                        "suggestion": (
                            "Switch to the process first with analyze_process(action='switch', address=<EPROCESS>), "
                            "then use dt nt!_TEB <teb_addr> or !thread <ETHREAD> (look for Teb field)"
                        ),
                        "category": "mode_mismatch"
                    }

                try:
                    if address:
                        send_command(f"~{address}s", timeout_ms=_get_timeout(f"~{address}s"))
                    teb_result = send_command("!teb", timeout_ms=_get_timeout("!teb"))
                    return {"output": teb_result, "context": "Thread Environment Block"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!teb", original_error=str(e))
                    return enhanced_error.to_dict()

            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["list", "switch", "info", "stack", "all_stacks", "teb"],
                    "kernel_note": "In kernel mode, 'address' is an ETHREAD pointer (from !process <eprocess> 4)",
                    "examples": [
                        "analyze_thread(action='list')  # kernel: threads of current process",
                        "analyze_thread(action='stack', address='<ETHREAD>', process_address='<EPROCESS>')",
                        "analyze_thread(action='all_stacks')  # kernel: stacks of first 8 threads"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_thread", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_memory(ctx: Context, action: str, address: str = "", type_name: str = "", length: int = 32) -> Union[str, Dict[str, Any]]:
        """
        Analyze memory and data structures.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "display", "type", "search", "pte", "regions"
            address: Memory address (required for most actions)
            type_name: Type name for structure display (required for "type" action)
            length: Number of bytes/elements to display (default: 32)
            
        Returns:
            Memory analysis results
        """
        logger.debug(f"Analyze memory action: {action}, address: {address}, type: {type_name}")
        
        try:
            # Detect debugging mode for mode-specific commands
            is_kernel_mode = detect_kernel_mode()
            logger.debug(f"Detected debugging mode: {'kernel' if is_kernel_mode else 'user'}")
            
            if action == "display":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Display memory content
                    result = send_command(f"dd {address} l{length}", timeout_ms=_get_timeout(f"dd {address} l{length}"))
                    return {"output": result, "address": address, "length": length}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"dd {address} l{length}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "type":
                if not address or not type_name:
                    missing = "address and type_name" if not address and not type_name else ("address" if not address else "type_name")
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param=missing)
                    return enhanced_error.to_dict()
                
                try:
                    # Display typed structure
                    result = send_command(f"dt {type_name} {address}", timeout_ms=_get_timeout(f"dt {type_name} {address}"))
                    return {"output": result, "type": type_name, "address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"dt {type_name} {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "search":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Search for pattern in memory range
                    search_cmd = f"s {address} L{length} {address[:8]}"  # Search for first 8 chars as pattern
                    result = send_command(search_cmd, timeout_ms=_get_timeout(search_cmd))
                    return {"output": result, "search_range": f"{address} L{length}"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=search_cmd, original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "pte":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Page Table Entry analysis
                    result = send_command(f"!pte {address}", timeout_ms=_get_timeout(f"!pte {address}"))
                    return {"output": result, "pte_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!pte {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "regions":
                try:
                    # Virtual memory regions
                    result = send_command("!vm", timeout_ms=_get_timeout("!vm"))
                    return {"output": result, "context": "Virtual memory regions"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!vm", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["display", "type", "search", "pte", "regions"],
                    "examples": [
                        "analyze_memory(action='display', address='0x1000')",
                        "analyze_memory(action='type', address='0x1000', type_name='_EPROCESS')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_memory", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_kernel(ctx: Context, action: str, address: str = "") -> Union[str, Dict[str, Any]]:
        """
        Analyze kernel objects and structures.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "object", "idt", "handles", "interrupts", "modules"
            address: Object address (required for "object", "interrupts")
            
        Returns:
            Kernel analysis results
        """
        logger.debug(f"Analyze kernel action: {action}, address: {address}")
        
        try:
            if action == "object":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_kernel", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    result = send_command(f"!object {address}", timeout_ms=_get_timeout(f"!object {address}"))
                    return {"output": result, "object_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!object {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "idt":
                try:
                    result = send_command("!idt", timeout_ms=_get_timeout("!idt"))
                    return {"output": result, "context": "Interrupt Descriptor Table"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!idt", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "handles":
                try:
                    result = send_command("!handle", timeout_ms=_get_timeout("!handle"))
                    return {"output": result, "context": "System handles"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!handle", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "interrupts":
                if address:
                    try:
                        result = send_command(f"!pic {address}", timeout_ms=_get_timeout(f"!pic {address}"))
                        return {"output": result, "interrupt_controller": address}
                    except Exception as e:
                        enhanced_error = enhance_error("execution", command=f"!pic {address}", original_error=str(e))
                        return enhanced_error.to_dict()
                else:
                    try:
                        result = send_command("!irql", timeout_ms=_get_timeout("!irql"))
                        return {"output": result, "context": "Current IRQL and interrupts"}
                    except Exception as e:
                        enhanced_error = enhance_error("execution", command="!irql", original_error=str(e))
                        return enhanced_error.to_dict()
                        
            elif action == "modules":
                try:
                    result = send_command("lm", timeout_ms=_get_timeout("lm"))
                    return {"output": result, "context": "Loaded modules"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="lm", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["object", "idt", "handles", "interrupts", "modules"],
                    "examples": [
                        "analyze_kernel(action='idt')",
                        "analyze_kernel(action='object', address='0xffffffff80000000')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_kernel", original_error=str(e))
            return enhanced_error.to_dict() 
