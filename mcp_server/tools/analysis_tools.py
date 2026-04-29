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
                        if process_address:
                            # Process-scoped: get threads of a specific process then dump each stack.
                            proc_info = send_command(f"!process {process_address} 4", timeout_ms=_get_timeout(f"!process {process_address} 4"))
                            thread_addrs = re.findall(r'THREAD\s+([0-9a-fA-F`]+)', proc_info)
                            # Switch VA space so user-mode symbols resolve.
                            proc_cmd = f".process /r /p {process_address}"
                            send_command(proc_cmd, timeout_ms=_get_timeout(proc_cmd))
                            stacks = []
                            for taddr in thread_addrs:
                                try:
                                    send_command(f".thread {taddr}", timeout_ms=_get_timeout(".thread"))
                                    stack = send_command(f"k {min(count, 20)}", timeout_ms=_get_timeout("k"))
                                    stacks.append({"thread": taddr, "stack": stack})
                                except Exception:
                                    stacks.append({"thread": taddr, "stack": "(failed to get stack)"})
                            return {
                                "process_address": process_address,
                                "thread_count": len(thread_addrs),
                                "stacks_shown": len(stacks),
                                "stacks": stacks,
                                "tip": "For system-wide hang analysis use analyze_kernel(action='stacks')"
                            }
                        else:
                            # System-wide: !stacks 2 covers ALL kernel threads across every process.
                            # This is the correct command for diagnosing system-level hangs/freezes.
                            result = send_command("!stacks 2", timeout_ms=_get_timeout("!stacks"))
                            return {
                                "output": result,
                                "note": (
                                    "System-wide kernel thread stacks via !stacks 2. "
                                    "To scope to a single process supply process_address='<EPROCESS>'."
                                ),
                                "tip": "Use analyze_kernel(action='running') for per-CPU running threads"
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
        Analyze memory, data structures, and pool allocations.

        **Memory leak / pool corruption workflow (Driver Verifier):**
          - analyze_memory(action='poolused')                  — rank drivers by pool usage
          - analyze_memory(action='poolfind', address='<tag>') — find all allocs with a tag
          - analyze_memory(action='pool', address='<addr>')    — inspect a specific pool block

        Args:
            ctx: The MCP context
            action: Action to perform:
                    "display"   - display memory as DWORDs (dd <addr> l<len>)
                    "type"      - display a typed structure (dt <type> <addr>)
                    "search"    - search for a byte/DWORD pattern in memory
                                  (uses type_name as the search pattern)
                    "pte"       - analyze Page Table Entry (!pte <addr>)
                    "regions"   - virtual memory regions (!vm)
                    "pool"      - analyze a pool block/allocation (!pool <addr>)
                                  USE THIS for pool corruption bugchecks (0x19 / 0xC2)
                    "poolused"  - list pool usage per driver, sorted by nonpaged size
                                  USE THIS to find the driver leaking the most pool memory
                    "poolfind"  - find all pool allocations with a given 4-char tag
                                  (address parameter = pool tag, e.g. 'Ddk ')
            address: Memory address (required for display/type/search/pte/pool/poolfind)
            type_name: Type name for 'type' action, or search pattern for 'search' action
            length: Number of bytes/DWORDs to display or search (default: 32)

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
                if not type_name:
                    return {
                        "error": "'search' action requires type_name as the search pattern",
                        "example": "analyze_memory(action='search', address='0xffff...', type_name='deadbeef', length=256)",
                        "note": "type_name is interpreted as a hex DWORD pattern for 's -d' search"
                    }

                try:
                    # s -d: search for a DWORD value in the given address range.
                    # type_name is repurposed as the pattern to search for.
                    search_cmd = f"s -d {address} L{length} {type_name}"
                    result = send_command(search_cmd, timeout_ms=_get_timeout(search_cmd))
                    return {
                        "output": result,
                        "search_range": f"{address} L{length}",
                        "pattern": type_name,
                        "command": search_cmd
                    }
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

            elif action == "pool":
                # Analyze a specific pool block.
                # In pool corruption crashes (.bugcheck param2 is usually the bad pool address).
                # Also useful after !verifier to inspect individual flagged allocations.
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                try:
                    result = send_command(f"!pool {address}", timeout_ms=_get_timeout("!pool"))
                    return {
                        "output": result,
                        "pool_address": address,
                        "context": "Pool block analysis",
                        "next_steps": [
                            "Look for 'Pool tag' to identify the owning driver (4-char tag)",
                            "'*** ERROR:' or 'BAD' lines indicate corruption",
                            "Use analyze_memory(action='poolfind', address='<tag>') to "
                            "find all allocations with that tag",
                            "Use 'lm' or '!poolused' to map pool tag to a driver name"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!pool {address}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "poolused":
                # List pool memory usage per driver, sorted by nonpaged pool size.
                # This is the definitive command for finding which driver is NOT freeing pool.
                # Verifier memory leak scenario: the driver with the largest NonPaged value
                # that should have freed on unload but didn't is the culprit.
                try:
                    # 4 = sort by nonpaged pool (descending) — biggest leakers first.
                    result = send_command("!poolused 4", timeout_ms=_get_timeout("!poolused"))
                    return {
                        "output": result,
                        "context": "Pool usage per driver, sorted by nonpaged pool (desc)",
                        "note": (
                            "The driver at the top with the largest 'Nonpaged' value is "
                            "the primary suspect for pool leaking. Note its pool tag."
                        ),
                        "next_steps": [
                            "Identify the driver with the largest NonPaged allocation",
                            "Note its 4-char pool tag (shown in the Tag column)",
                            "Use analyze_memory(action='poolfind', address='<tag>') "
                            "to enumerate all outstanding allocations with that tag",
                            "Confirm the driver with 'lm m <driver_name>'"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!poolused 4", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "poolfind":
                # Find all outstanding pool allocations with a given 4-char pool tag.
                # Use after poolused identifies the tag of the leaking driver.
                if not address:
                    return {
                        "error": "'poolfind' requires address parameter as the pool tag (e.g. 'Ddk ')",
                        "example": "analyze_memory(action='poolfind', address='Ddk ')",
                        "note": "Pool tags are 4 characters; pad with spaces if needed"
                    }
                try:
                    result = send_command(f"!poolfind {address}", timeout_ms=_get_timeout("!poolfind"))
                    return {
                        "output": result,
                        "pool_tag": address,
                        "context": f"All pool allocations with tag '{address}'",
                        "next_steps": [
                            "Each entry shows the pool block address and size",
                            "Use analyze_memory(action='pool', address='<block_addr>') "
                            "to inspect a specific block's content and allocation stack",
                            "If Driver Verifier is enabled, allocation stacks may be available "
                            "via 'dt nt!_POOL_TRACKER_BIG_PAGES <addr>'"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!poolfind {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["display", "type", "search", "pte", "regions",
                                          "pool", "poolused", "poolfind"],
                    "memory_leak_workflow": [
                        "1. analyze_memory(action='poolused')                   — rank drivers by NonPaged pool",
                        "2. analyze_memory(action='poolfind', address='<tag>')  — find all allocs with tag",
                        "3. analyze_memory(action='pool', address='<block>')    — inspect specific block"
                    ],
                    "examples": [
                        "analyze_memory(action='display', address='0x1000')",
                        "analyze_memory(action='type', address='0x1000', type_name='_EPROCESS')",
                        "analyze_memory(action='search', address='0xffff0000', type_name='deadbeef', length=256)",
                        "analyze_memory(action='pool', address='0xffff8001a2b3c000')",
                        "analyze_memory(action='poolused')",
                        "analyze_memory(action='poolfind', address='Ddk ')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_memory", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_kernel(ctx: Context, action: str, address: str = "") -> Union[str, Dict[str, Any]]:
        """
        Analyze kernel objects, structures, and system-wide state.

        **Driver Verifier crash (bugcheck 0xC4) diagnosis workflow:**

          Step 1 — Auto crash analysis:   analyze_kernel(action='bugcheck')
                     (includes !verifier automatically)
          Step 2 — Verifier details:      analyze_kernel(action='verifier')
          Step 3 — Find leaking driver:   analyze_memory(action='poolused')
          Step 4 — Inspect pool block:    analyze_memory(action='pool', address='<param2 from .bugcheck>')

        **General driver crash (bugcheck/BSOD) diagnosis workflow:**

          Step 1 — Auto crash analysis:   analyze_kernel(action='bugcheck')
          Step 2 — Identify the driver:   analyze_kernel(action='modules') + 'lm a <addr>'
          Step 3 — If pool corruption:    analyze_memory(action='pool', address='<param2>')
          Step 4 — If IRP related:        run_command('!irp <addr>') with the IRP address

        **System hang / freeze diagnosis workflow:**

          Step 1 — Break into target:     break_into_target()
          Step 2 — Auto hang analysis:    analyze_kernel(action='analyze')
          Step 3 — Per-CPU running state: analyze_kernel(action='running')
          Step 4 — All kernel stacks:     analyze_kernel(action='stacks')
          Step 5 — Lock contention:       analyze_kernel(action='locks')
          Step 6 — DPC queue:             analyze_kernel(action='dpcs')

        Args:
            ctx: The MCP context
            action: Action to perform:
                    "bugcheck"   - full crash/BSOD analysis: .bugcheck + !analyze -v + call stack
                                   USE THIS for driver crashes and blue screens
                    "analyze"    - hang analysis (!analyze -v -hang), for frozen system
                                   USE THIS when you manually break into a running/frozen system
                    "running"    - threads running on each CPU with stacks (!running -t)
                    "stacks"     - all non-idle kernel thread stacks system-wide (!stacks 2)
                    "locks"      - executive resource / mutex lock contention (!locks)
                    "dpcs"       - deferred procedure call queue (!dpcs)
                    "verifier"   - Driver Verifier state + memory leak analysis
                                   (!verifier 3 + !poolused 4). USE THIS for 0xC4 crashes
                                   and memory leak diagnosis
                    "object"     - inspect a kernel object (!object <addr>)
                    "idt"        - Interrupt Descriptor Table (!idt)
                    "handles"    - system handles (!handle)
                    "interrupts" - current IRQL or PIC state (!irql / !pic)
                    "modules"    - loaded kernel modules (lm)
            address: Object address (required for "object" and "interrupts" with PIC)

        Returns:
            Kernel analysis results
        """
        logger.debug(f"Analyze kernel action: {action}, address: {address}")
        
        try:
            if action == "bugcheck":
                # Full driver crash / BSOD analysis workflow.
                # This is the correct entry point when the target has crashed (blue screen).
                # Do NOT use -hang here: -hang forces hang-analysis mode and ignores the
                # actual bugcheck exception, giving wrong results for crash analysis.
                crash_results = []

                # Step 1: Get raw bugcheck code and parameters.
                try:
                    bc_out = send_command(".bugcheck", timeout_ms=_get_timeout(".bugcheck"))
                    crash_results.append({"step": "bugcheck_info", "output": bc_out})
                except Exception as e:
                    crash_results.append({"step": "bugcheck_info", "error": str(e)})

                # Step 2: Full automatic crash analysis — WinDbg reads the exception record
                # and maps it to the responsible driver automatically.
                try:
                    analyze_out = send_command("!analyze -v", timeout_ms=_get_timeout("!analyze -v"))
                    crash_results.append({"step": "crash_analysis", "output": analyze_out})
                except Exception as e:
                    crash_results.append({"step": "crash_analysis", "error": str(e)})

                # Step 3: Driver Verifier state — ALWAYS run this.
                # If bugcheck is 0xC4 (DRIVER_VERIFIER_DETECTED_VIOLATION) this output
                # contains the critical violation code in param1 (e.g. 0x62 = memory leak,
                # 0x1 = special pool, 0x52 = mismatched free).
                try:
                    verifier_out = send_command("!verifier", timeout_ms=_get_timeout("!verifier"))
                    crash_results.append({"step": "verifier_state", "output": verifier_out})
                except Exception as e:
                    crash_results.append({"step": "verifier_state", "error": str(e)})

                # Step 4: Call stack of the crashing thread (with parameters).
                try:
                    stack_out = send_command("kP 30", timeout_ms=_get_timeout("kP"))
                    crash_results.append({"step": "crash_stack", "output": stack_out})
                except Exception as e:
                    crash_results.append({"step": "crash_stack", "error": str(e)})

                return {
                    "success": True,
                    "context": "Driver crash / bugcheck analysis",
                    "steps": crash_results,
                    "next_steps": [
                        "Find 'MODULE_NAME' and 'IMAGE_NAME' in crash_analysis output — that is the responsible driver",
                        "Find 'STACK_TEXT' in crash_analysis to trace the exact failure path",
                        "If bugcheck is 0xC4 (DRIVER_VERIFIER_DETECTED_VIOLATION): "
                        "check verifier_state output; param1 is the violation code. "
                        "Then run analyze_kernel(action='verifier') for details, "
                        "and analyze_memory(action='poolused') to find the leaking driver",
                        "If bugcheck is 0xC2 (BAD_POOL_CALLER) or 0x19 (BAD_POOL_HEADER): "
                        "run analyze_memory(action='pool', address='<param2_from_bugcheck>')",
                        "If bugcheck is 0xD1 (DRIVER_IRQL_NOT_LESS_OR_EQUAL): the driver is "
                        "accessing paged memory at elevated IRQL — see STACK_TEXT for the driver",
                        "If bugcheck is 0x7E or 0x8E (unexpected kernel exception): check "
                        "EXCEPTION_CODE and the faulting instruction in STACK_TEXT",
                        "Use 'lm a <address>' to identify any unknown address as a module",
                        "Use analyze_kernel(action='modules') then 'lm a <addr>' to confirm the driver"
                    ],
                    "common_bugchecks": {
                        "0x0000000A (IRQL_NOT_LESS_OR_EQUAL)": "Driver accessing paged memory at elevated IRQL",
                        "0x0000001E (KMODE_EXCEPTION_NOT_HANDLED)": "Unhandled kernel exception, check STOP parameters",
                        "0x00000019 (BAD_POOL_HEADER)": "Pool corruption — use analyze_memory(action='pool', address='<param2>')",
                        "0x000000C2 (BAD_POOL_CALLER)": "Invalid pool allocation — use analyze_memory(action='pool', address='<param2>')",
                        "0x000000C4 (DRIVER_VERIFIER_DETECTED_VIOLATION)": "Verifier triggered — check verifier_state step; param1 violation codes: 0x62=memory leak, 0x1=special pool, 0x52=mismatched free",
                        "0x000000E6 (DRIVER_VERIFIER_DMA_VIOLATION)": "DMA violation detected by Driver Verifier",
                        "0x000000D1 (DRIVER_IRQL_NOT_LESS_OR_EQUAL)": "Driver IRQL violation",
                        "0x000000FC (ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY)": "DEP violation in driver",
                        "0x00000050 (PAGE_FAULT_IN_NONPAGED_AREA)": "Invalid memory access in driver",
                        "0x0000007E (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)": "System thread exception",
                        "0x00000133 (DPC_WATCHDOG_VIOLATION)": "DPC ran too long — check !dpcs"
                    }
                }

            elif action == "analyze":
                # Hang analysis — use ONLY when the system is frozen/unresponsive and you
                # manually broke in (Ctrl+Break / break_into_target). The -hang flag forces
                # WinDbg into hang-analysis mode even without an active exception.
                # WARNING: Do NOT use this for crash/BSOD analysis — use action='bugcheck' instead.
                try:
                    result = send_command("!analyze -v -hang", timeout_ms=_get_timeout("!analyze -v"))
                    return {
                        "output": result,
                        "context": "Hang analysis (manually broken-in system)",
                        "note": (
                            "This uses !analyze -v -hang which is designed for frozen systems. "
                            "If the system CRASHED (BSOD), use analyze_kernel(action='bugcheck') instead."
                        ),
                        "next_steps": [
                            "Review 'BLOCKING_THREAD' and 'STACK_TEXT' sections",
                            "Identify the module in 'MODULE_NAME' and 'IMAGE_NAME'",
                            "Run analyze_kernel(action='running') to see per-CPU state",
                            "Run analyze_kernel(action='stacks') for all thread stacks"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!analyze -v -hang", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "running":
                # !running -t shows what each processor is executing RIGHT NOW.
                # This is the fastest way to see which CPUs are stuck and on what driver.
                try:
                    result = send_command("!running -t", timeout_ms=_get_timeout("!running"))
                    return {
                        "output": result,
                        "context": "Threads currently running on each CPU",
                        "note": (
                            "Each block shows one CPU. Look for CPUs stuck in the same "
                            "driver function repeatedly — that driver is likely the culprit."
                        ),
                        "next_steps": [
                            "If a CPU is in a spin loop in driver X -> X is likely hanging the system",
                            "Run analyze_kernel(action='stacks') for all waiting threads",
                            "Run analyze_kernel(action='locks') to find lock contention"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!running -t", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "stacks":
                # !stacks 2 dumps kernel stacks for ALL threads system-wide (skips idle).
                # This is the definitive command for finding what all threads are doing.
                try:
                    result = send_command("!stacks 2", timeout_ms=_get_timeout("!stacks"))
                    return {
                        "output": result,
                        "context": "All non-idle kernel thread stacks (system-wide)",
                        "note": (
                            "!stacks 2 filters out common idle frames and groups similar stacks. "
                            "Look for large groups of threads all waiting on the same function — "
                            "that function's owning module is a strong hang candidate."
                        ),
                        "next_steps": [
                            "Identify modules appearing at the top of many stuck stacks",
                            "Use analyze_kernel(action='locks') to check specific lock holders",
                            "Use analyze_thread(action='info', address='<ETHREAD>') for details"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!stacks 2", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "locks":
                # !locks shows all held ERESOURCE executive locks and their owner threads.
                # Critical for diagnosing deadlocks and resource starvation hangs.
                try:
                    result = send_command("!locks", timeout_ms=_get_timeout("!locks"))
                    return {
                        "output": result,
                        "context": "Kernel executive resource (ERESOURCE) lock state",
                        "note": (
                            "Look for resources with ExclusiveOwner or many SharedOwners. "
                            "The owning thread's call stack will identify the responsible module."
                        ),
                        "next_steps": [
                            "Note the 'ExclusiveOwner' thread address",
                            "Run analyze_thread(action='stack', address='<owner ETHREAD>') "
                            "to see what that thread is doing",
                            "Run analyze_kernel(action='dpcs') if the owner is a DPC routine"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!locks", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "dpcs":
                # !dpcs shows the deferred procedure call queue for each CPU.
                # A long-running or starved DPC can freeze the whole system.
                try:
                    result = send_command("!dpcs", timeout_ms=_get_timeout("!dpcs"))
                    return {
                        "output": result,
                        "context": "Deferred Procedure Call (DPC) queue state",
                        "note": (
                            "A DPC that never completes will prevent the CPU from returning "
                            "to normal thread scheduling. The DPC routine shown is the suspect."
                        ),
                        "next_steps": [
                            "Identify the DPC routine and its owning driver",
                            "Use 'lm a <DPC_addr>' to find the module",
                            "Run analyze_kernel(action='running') to see if CPUs are spinning in this DPC"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!dpcs", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "verifier":
                # Driver Verifier state and memory leak analysis.
                # Primary use case: system crashed with bugcheck 0xC4
                # (DRIVER_VERIFIER_DETECTED_VIOLATION) or memory leaks are suspected.
                verifier_results = []

                # Step 1: Verifier flags + per-driver statistics.
                # !verifier 3 = FLAGS(1) | STATISTICS(2): shows what verifier checks are
                # enabled and how many violations each driver caused.
                try:
                    v3_out = send_command("!verifier 3", timeout_ms=_get_timeout("!verifier"))
                    verifier_results.append({"step": "verifier_flags_and_stats", "output": v3_out})
                except Exception as e:
                    verifier_results.append({"step": "verifier_flags_and_stats", "error": str(e)})

                # Step 2: Pool usage sorted by nonpaged pool size (descending).
                # !poolused 4 reveals which driver has allocated the most nonpaged pool
                # without freeing it — the top entry is almost always the leaking driver.
                try:
                    pu_out = send_command("!poolused 4", timeout_ms=_get_timeout("!poolused"))
                    verifier_results.append({"step": "pool_usage_by_nonpaged", "output": pu_out})
                except Exception as e:
                    verifier_results.append({"step": "pool_usage_by_nonpaged", "error": str(e)})

                # Step 3: Verifier driver list — shows exactly which drivers are under test.
                try:
                    v4_out = send_command("!verifier 4", timeout_ms=_get_timeout("!verifier"))
                    verifier_results.append({"step": "verified_drivers", "output": v4_out})
                except Exception as e:
                    verifier_results.append({"step": "verified_drivers", "error": str(e)})

                return {
                    "success": True,
                    "context": "Driver Verifier state and memory leak analysis",
                    "steps": verifier_results,
                    "next_steps": [
                        "In pool_usage_by_nonpaged: the driver at the top with the largest "
                        "'Nonpaged' allocation is the leaking driver",
                        "Note the 4-char pool tag next to the driver name — use "
                        "analyze_memory(action='poolfind', address='<tag>') to find all allocations",
                        "In verifier_flags_and_stats: look for drivers with non-zero "
                        "'CurrentPagedPoolAllocations' or 'CurrentNonPagedPoolAllocations' "
                        "at shutdown/crash time",
                        "Use analyze_memory(action='pool', address='<pool_addr>') to inspect "
                        "a specific pool block from the .bugcheck parameters",
                        "If verifier_flags_and_stats shows 0xC4 violation code 0x62: this IS "
                        "a memory leak — the driver allocated pool and didn't free it on unload"
                    ],
                    "verifier_violation_codes": {
                        "0x00000001": "Special pool: corrupted allocations adjacent to block",
                        "0x00000052": "Mismatched free (ExFreePool type != allocation type)",
                        "0x00000062": "Memory leak on driver unload (pool not freed)",
                        "0x00000063": "Memory leak on driver unload (contiguous memory not freed)",
                        "0x00000064": "Memory leak on driver unload (common buffer not freed)",
                        "0x00000065": "Memory leak on driver unload (MDL not freed)"
                    }
                }

            elif action == "object":
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
                    "available_actions": [
                        "bugcheck", "analyze", "verifier", "running", "stacks", "locks", "dpcs",
                        "object", "idt", "handles", "interrupts", "modules"
                    ],
                    "verifier_crash_workflow": [
                        "1. analyze_kernel(action='bugcheck')   — auto crash analysis (includes !verifier)",
                        "2. analyze_kernel(action='verifier')   — verifier state + !poolused 4 leak ranking",
                        "3. analyze_memory(action='poolused')   — full pool usage by driver",
                        "4. analyze_memory(action='pool', address='<param2>') — inspect specific pool block"
                    ],
                    "crash_diagnosis_workflow": [
                        "1. analyze_kernel(action='bugcheck')  — .bugcheck + !analyze -v + !verifier + kP",
                        "2. analyze_kernel(action='modules')   — lm to identify driver by address",
                        "3. analyze_memory(action='pool', address='<addr>') — if pool corruption bugcheck",
                        "4. run_command('!irp <addr>')         — if IRP-related crash"
                    ],
                    "hang_diagnosis_workflow": [
                        "1. break_into_target()                — interrupt running system",
                        "2. analyze_kernel(action='analyze')   — !analyze -v -hang (FOR HANG/FREEZE)",
                        "3. analyze_kernel(action='running')   — !running -t (per-CPU state)",
                        "4. analyze_kernel(action='stacks')    — !stacks 2 (all thread stacks)",
                        "5. analyze_kernel(action='locks')     — !locks (lock contention)",
                        "6. analyze_kernel(action='dpcs')      — !dpcs (DPC queue)"
                    ],
                    "examples": [
                        "analyze_kernel(action='bugcheck')   # driver crash / BSOD",
                        "analyze_kernel(action='analyze')    # system hang / freeze",
                        "analyze_kernel(action='running')",
                        "analyze_kernel(action='stacks')",
                        "analyze_kernel(action='locks')",
                        "analyze_kernel(action='idt')",
                        "analyze_kernel(action='object', address='0xffffffff80000000')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_kernel", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_code(ctx: Context, action: str, module: str = "", symbol: str = "", address: str = "", length: int = 20, frame: int = -1) -> Union[str, Dict[str, Any]]:
        """
        Analyze driver code with PDB symbols and disassembly.

        **Typical workflow — "why did execution reach this point?"**

          Step 1 — Verify symbols:  analyze_code(action='symbols', module='mydriver')
          Step 2 — Find function:   analyze_code(action='find', module='mydriver', symbol='*IrpHandler*')
          Step 3 — Disassemble:     analyze_code(action='disasm', symbol='mydriver!MyIrpHandler')
          Step 4 — See call sites:  analyze_code(action='calls', symbol='mydriver!MyIrpHandler')
          Step 5 — Stack + frames:  analyze_thread(action='stack')
                                    analyze_code(action='frame', frame=2)   ← locals of frame 2
          Step 6 — Registers:       analyze_code(action='registers')
          Step 7 — Nearest symbol:  analyze_code(action='nearest', address='<rip value>')

        **PDB private symbol setup:**

          When a private PDB is available locally on the debugger machine:
            analyze_code(action='add_sympath', symbol='C:\\\\Symbols\\\\MyDriver')
          Then force-reload:
            analyze_code(action='reload', module='mydriver.sys')

        Args:
            ctx: The MCP context
            action: Action to perform:
                    "symbols"    - check symbol status for a module (lmv m <module>)
                    "find"       - find symbols matching a pattern (x <module>!<symbol>)
                                   use '*' wildcards, e.g. symbol='*Dispatch*'
                    "nearest"    - find nearest symbol to an address (ln <address>)
                                   essential for mapping raw RIP/EIP from a crash to code
                    "disasm"     - disassemble a whole function following all branches
                                   (uf <module>!<symbol>  or  uf <address>)
                    "disasm_raw" - linear disassembly from an address (u <address> L<length>)
                    "calls"      - show only call instructions inside a function (uf /c <symbol>)
                                   reveals the call graph without full disassembly noise
                    "frame"      - switch to a specific stack frame and display local variables
                                   (.frame <n>  +  dv)  — use after analyze_thread(action='stack')
                    "registers"  - show CPU registers at the current context (r)
                    "source"     - show source lines around current instruction (lsa .  or  lsa <addr>)
                    "add_sympath"- append a directory to the symbol search path (.sympath+ <path>)
                                   use with symbol=<path>
                    "reload"     - reload symbols for a specific module or all (.reload /f <module>)
            module: Module/driver name (without .sys), e.g. 'mydriver' or 'nt'
            symbol: Symbol pattern or full qualified symbol 'module!function', or path for add_sympath
            address: Memory address (hex), used for nearest/disasm_raw/source
            length: Number of instructions for disasm_raw (default: 20)
            frame: Stack frame number for 'frame' action (default: -1 = current frame 0)

        Returns:
            Code analysis results with next-step guidance
        """
        logger.debug(f"Analyze code action: {action}, module: {module}, symbol: {symbol}, address: {address}")

        try:
            if action == "symbols":
                # Check PDB symbol status for a module.
                # The 'pdb symbols' line in lmv output confirms a private PDB was loaded.
                # 'export symbols' means only the export table was used — no type info.
                if not module:
                    return {
                        "error": "'symbols' action requires the 'module' parameter",
                        "example": "analyze_code(action='symbols', module='mydriver')",
                        "tip": "Use the module name without .sys extension"
                    }
                try:
                    result = send_command(f"lmv m {module}", timeout_ms=_get_timeout(f"lmv m {module}"))
                    sympath = send_command(".sympath", timeout_ms=_get_timeout(".sympath"))
                    has_pdb = "pdb symbols" in result.lower()
                    return {
                        "output": result,
                        "module": module,
                        "pdb_loaded": has_pdb,
                        "symbol_path": sympath.strip(),
                        "next_steps": (
                            [
                                "PDB loaded — private symbols available",
                                f"Find functions: analyze_code(action='find', module='{module}', symbol='*')",
                                f"Disassemble: analyze_code(action='disasm', symbol='{module}!FunctionName')"
                            ] if has_pdb else [
                                "Only export symbols — no type/line info available",
                                "If you have the PDB file, add its folder: "
                                "analyze_code(action='add_sympath', symbol='C:\\\\path\\\\to\\\\pdb')",
                                f"Then force reload: analyze_code(action='reload', module='{module}.sys')",
                                "Or configure a symbol server: .symfix+ C:\\\\SymCache"
                            ]
                        )
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"lmv m {module}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "find":
                # Find symbols matching a wildcard pattern inside a module.
                # This is the first step to locate a function by name when you have PDB.
                if not module and not symbol:
                    return {
                        "error": "'find' requires at least 'module' (and optionally 'symbol' as a wildcard pattern)",
                        "example": "analyze_code(action='find', module='mydriver', symbol='*Dispatch*')",
                        "tip": "Omit symbol to list ALL exported symbols of the module"
                    }
                pattern = f"{module}!{symbol}" if module else symbol
                if module and not symbol:
                    pattern = f"{module}!*"
                try:
                    result = send_command(f"x {pattern}", timeout_ms=_get_timeout(f"x {pattern}"))
                    # Extract matched symbols for structured output
                    matches = re.findall(r'([0-9a-fA-F`]+)\s+(\S+)', result)
                    return {
                        "output": result,
                        "pattern": pattern,
                        "match_count": len(matches),
                        "matches": [{"address": m[0], "symbol": m[1]} for m in matches[:30]],
                        "next_steps": [
                            f"Disassemble a function: analyze_code(action='disasm', symbol='<module>!<function>')",
                            f"Show call graph: analyze_code(action='calls', symbol='<module>!<function>')"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"x {pattern}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "nearest":
                # Map a raw address (e.g. a crashed RIP/EIP, or an unknown call target) to
                # the nearest named symbol.  This answers "what function is this address in?"
                if not address:
                    return {
                        "error": "'nearest' requires the 'address' parameter",
                        "example": "analyze_code(action='nearest', address='0xfffff80012345678')",
                        "tip": "Use the RIP/EIP value from a crash or from a stack frame"
                    }
                try:
                    result = send_command(f"ln {address}", timeout_ms=_get_timeout(f"ln {address}"))
                    return {
                        "output": result,
                        "address": address,
                        "next_steps": [
                            "Copy the symbol name above to disassemble the function:",
                            f"analyze_code(action='disasm', symbol='<symbol from output>')",
                            "Or verify full module info: analyze_code(action='symbols', module='<module>')"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"ln {address}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "disasm":
                # Full function disassembly following all branches.
                # 'uf' tracks conditional jumps and shows the complete control flow graph
                # in topological order — much better than raw linear 'u' for understanding logic.
                # Requires either a symbol (module!function) or an address.
                target = symbol if symbol else address
                if not target:
                    return {
                        "error": "'disasm' requires 'symbol' (e.g. 'mydriver!MyFunc') or 'address'",
                        "example": "analyze_code(action='disasm', symbol='mydriver!DriverEntry')",
                        "tip": "Use analyze_code(action='find') first to locate the exact symbol name"
                    }
                try:
                    result = send_command(f"uf {target}", timeout_ms=_get_timeout(f"uf {target}"))
                    return {
                        "output": result,
                        "target": target,
                        "note": (
                            "'uf' shows the full control-flow graph of the function. "
                            "Branches are shown in reachability order, not linear address order."
                        ),
                        "next_steps": [
                            "To see only call sites: analyze_code(action='calls', symbol='" + target + "')",
                            "To inspect a call target: analyze_code(action='nearest', address='<call target addr>')",
                            "To see parameters at runtime: analyze_code(action='frame', frame=0) after breaking"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"uf {target}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "disasm_raw":
                # Linear disassembly from a specific address.
                # Use this when you want to see N instructions starting at an exact address,
                # regardless of function boundaries (e.g. mid-function after a crash).
                if not address:
                    return {
                        "error": "'disasm_raw' requires the 'address' parameter",
                        "example": "analyze_code(action='disasm_raw', address='0xfffff800`12345678', length=30)"
                    }
                try:
                    result = send_command(f"u {address} L{length}", timeout_ms=_get_timeout(f"u {address} L{length}"))
                    return {
                        "output": result,
                        "address": address,
                        "instructions": length
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"u {address} L{length}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "calls":
                # Show only the CALL instructions inside a function.
                # 'uf /c' is the fastest way to build a call-graph without reading
                # through the full disassembly.  The output lists each call target
                # with its address and symbol, so you immediately see what the function calls.
                target = symbol if symbol else address
                if not target:
                    return {
                        "error": "'calls' requires 'symbol' or 'address'",
                        "example": "analyze_code(action='calls', symbol='mydriver!MyIrpHandler')"
                    }
                try:
                    result = send_command(f"uf /c {target}", timeout_ms=_get_timeout(f"uf /c {target}"))
                    return {
                        "output": result,
                        "target": target,
                        "note": "Each line shows a call instruction and its resolved target symbol.",
                        "next_steps": [
                            "Disassemble a callee: analyze_code(action='disasm', symbol='<callee symbol>')",
                            "Check if a callee is suspicious: analyze_code(action='nearest', address='<addr>')"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"uf /c {target}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "frame":
                # Switch to a specific call stack frame and show local variables.
                # After analyze_thread(action='stack') reveals the call chain, use this
                # to drill into each frame to see argument values and local state.
                frame_num = frame if frame >= 0 else 0
                try:
                    # Switch frame
                    frame_result = send_command(f".frame {frame_num}", timeout_ms=_get_timeout(f".frame {frame_num}"))
                    # Display locals and parameters
                    dv_result = send_command("dv /t /v", timeout_ms=_get_timeout("dv /t /v"))
                    # Also get registers at this frame
                    reg_result = send_command("r rip, rsp, rbp", timeout_ms=_get_timeout("r rip, rsp, rbp"))
                    return {
                        "frame": frame_num,
                        "frame_info": frame_result,
                        "local_variables": dv_result,
                        "frame_registers": reg_result,
                        "note": (
                            "dv /t /v shows local variables with their types and memory addresses. "
                            "Use 'dt <type> <addr>' to expand a struct pointer."
                        ),
                        "next_steps": [
                            f"Inspect previous frame: analyze_code(action='frame', frame={frame_num + 1})",
                            "Disassemble the function in this frame: see 'frame_info' for the symbol name",
                            "Expand a struct: analyze_memory(action='type', address='<addr>', type_name='<type>')"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f".frame {frame_num}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "registers":
                # Dump all CPU registers at the current context.
                # After a crash or breakpoint this shows RIP (instruction pointer),
                # RSP (stack pointer), and general-purpose registers with their values.
                try:
                    result = send_command("r", timeout_ms=_get_timeout("r"))
                    rip_match = re.search(r'rip=([0-9a-fA-F`]+)', result, re.IGNORECASE)
                    rip = rip_match.group(1) if rip_match else None
                    return {
                        "output": result,
                        "rip": rip,
                        "next_steps": (
                            [
                                f"Find what function RIP belongs to: analyze_code(action='nearest', address='{rip}')",
                                f"Disassemble around RIP: analyze_code(action='disasm_raw', address='{rip}', length=20)"
                            ] if rip else [
                                "Use analyze_code(action='nearest', address='<rip value>') to map RIP to a symbol"
                            ]
                        )
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="r", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "source":
                # Show source lines around the current or a specific instruction.
                # Requires that source files are accessible (.srcpath must be configured).
                # 'lsa .' shows lines around the current instruction pointer.
                try:
                    if address:
                        result = send_command(f"lsa {address}", timeout_ms=_get_timeout(f"lsa {address}"))
                    else:
                        result = send_command("lsa .", timeout_ms=_get_timeout("lsa ."))
                    srcpath = send_command(".srcpath", timeout_ms=_get_timeout(".srcpath"))
                    return {
                        "output": result,
                        "source_path": srcpath.strip(),
                        "tip": (
                            "If source is not found, add the source directory: "
                            ".srcpath+ C:\\\\path\\\\to\\\\driver\\\\src"
                        )
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="lsa .", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "add_sympath":
                # Append a local PDB directory to the symbol search path.
                # After this, run analyze_code(action='reload', module='<driver>.sys')
                # to pick up the private PDB.
                path = symbol if symbol else address
                if not path:
                    return {
                        "error": "'add_sympath' requires the PDB folder path in the 'symbol' parameter",
                        "example": "analyze_code(action='add_sympath', symbol='C:\\\\Symbols\\\\MyDriver')"
                    }
                try:
                    result = send_command(f".sympath+ {path}", timeout_ms=_get_timeout(f".sympath+ {path}"))
                    new_path = send_command(".sympath", timeout_ms=_get_timeout(".sympath"))
                    return {
                        "output": result,
                        "updated_sympath": new_path.strip(),
                        "next_steps": [
                            f"Force reload symbols for your driver: "
                            f"analyze_code(action='reload', module='<driver>.sys')"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f".sympath+ {path}", original_error=str(e))
                    return enhanced_error.to_dict()

            elif action == "reload":
                # Force-reload symbols for a specific module.
                # Use after add_sympath or after copying a PDB to the symbol cache.
                # .reload /f forces an immediate load even if symbols were previously
                # loaded from a different source.
                mod = module if module else symbol
                if not mod:
                    return {
                        "error": "'reload' requires 'module' (the .sys filename, e.g. 'mydriver.sys')",
                        "example": "analyze_code(action='reload', module='mydriver.sys')"
                    }
                try:
                    cmd = f".reload /f {mod}"
                    result = send_command(cmd, timeout_ms=_get_timeout(cmd))
                    # Verify what was loaded
                    base = mod.replace(".sys", "").replace(".dll", "").replace(".exe", "")
                    verify = send_command(f"lmv m {base}", timeout_ms=_get_timeout(f"lmv m {base}"))
                    has_pdb = "pdb symbols" in verify.lower()
                    return {
                        "reload_output": result,
                        "symbol_status": verify,
                        "pdb_loaded": has_pdb,
                        "next_steps": [
                            f"Find functions: analyze_code(action='find', module='{base}', symbol='*')"
                        ] if has_pdb else [
                            "PDB not found after reload — check that the .pdb file is in the sympath directory",
                            f"Current sympath: run analyze_code(action='symbols', module='{base}') to verify"
                        ]
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f".reload /f {mod}", original_error=str(e))
                    return enhanced_error.to_dict()

            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": [
                        "symbols", "find", "nearest", "disasm", "disasm_raw",
                        "calls", "frame", "registers", "source", "add_sympath", "reload"
                    ],
                    "recommended_workflow": [
                        "1. analyze_code(action='symbols', module='mydriver')         — verify PDB loaded",
                        "2. analyze_code(action='add_sympath', symbol='C:\\\\PDB')   — add PDB folder if needed",
                        "3. analyze_code(action='reload', module='mydriver.sys')      — force load PDB",
                        "4. analyze_code(action='find', module='mydriver', symbol='*Dispatch*') — find functions",
                        "5. analyze_code(action='disasm', symbol='mydriver!Function') — full disassembly",
                        "6. analyze_code(action='calls', symbol='mydriver!Function')  — call graph",
                        "7. analyze_thread(action='stack')                            — call stack at crash",
                        "8. analyze_code(action='frame', frame=2)                     — locals of frame 2",
                        "9. analyze_code(action='registers')                          — CPU registers",
                        "10. analyze_code(action='nearest', address='<rip>')          — map address to symbol"
                    ],
                    "examples": [
                        "analyze_code(action='symbols', module='mydriver')",
                        "analyze_code(action='find', module='mydriver', symbol='*Irp*')",
                        "analyze_code(action='disasm', symbol='mydriver!MyDispatchRoutine')",
                        "analyze_code(action='calls', symbol='mydriver!DriverEntry')",
                        "analyze_code(action='nearest', address='0xfffff80012345600')",
                        "analyze_code(action='frame', frame=0)",
                        "analyze_code(action='registers')"
                    ]
                }

        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_code", original_error=str(e))
            return enhanced_error.to_dict()
