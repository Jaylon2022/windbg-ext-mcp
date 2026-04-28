#include "pch.h"
#include "ipc/mcp_server.h"
#include <sstream>
#include <sddl.h>       // ConvertStringSecurityDescriptorToSecurityDescriptorA
#include <WDBGEXTS.H>

// Buffer size for reading from the pipe
constexpr DWORD BUFFER_SIZE = 4096;

MCPServer::MCPServer() : m_running(false), m_stopEvent(NULL) {
}

MCPServer::~MCPServer() {
    Stop();
}

bool MCPServer::Start(const std::string& pipeName) {
    if (m_running) {
        // Server already running
        return true;
    }

    m_pipeName = pipeName;
    m_running = true;
    
    // Start server thread
    m_serverThread = std::thread(&MCPServer::PipeServerThread, this);
    
    return true;
}

void MCPServer::Stop() {
    if (!m_running)
        return;
        
    m_running = false;

    // Signal the stop event so PipeServerThread wakes up from ConnectNamedPipe
    if (m_stopEvent) {
        SetEvent(m_stopEvent);
    }
    
    // Mark all clients as inactive so their handler threads exit
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (auto& client : m_clients) {
            client->active = false;
        }
    }
    
    // Wait for server thread to terminate
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }
    
    // Wait for all client threads to terminate and clean up
    CleanupDisconnectedClients();
}

bool MCPServer::IsRunning() const {
    return m_running;
}

void MCPServer::RegisterHandler(const std::string& command, MessageHandler handler) {
    m_handlers[command] = handler;
}

bool MCPServer::SendMessage(const json& message, HANDLE clientPipe) {
    if (!m_running)
        return false;
        
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    for (auto& client : m_clients) {
        if (client->hPipe == clientPipe) {
            std::lock_guard<std::mutex> queueLock(client->queueMutex);
            client->outgoingMessages.push(message);
            client->queueCondition.notify_one();
            return true;
        }
    }
    
    return false; // Client not found
}

bool MCPServer::BroadcastMessage(const json& message) {
    if (!m_running)
        return false;
        
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    for (auto& client : m_clients) {
        std::lock_guard<std::mutex> queueLock(client->queueMutex);
        client->outgoingMessages.push(message);
        client->queueCondition.notify_one();
    }
    
    return true;
}

HANDLE MCPServer::CreatePipeInstance() {
    // Build a security descriptor that restricts pipe access to the process
    // owner, SYSTEM, and the Administrators group.  NULL security attributes
    // would allow any local process to connect and issue arbitrary WinDbg
    // commands, which is a significant privilege-escalation risk given that
    // this extension can manipulate kernel state.
    //
    // SDDL breakdown:
    //   D:P             – protected DACL (no inheritance from parent)
    //   (A;;GA;;;OW)    – GENERIC_ALL to the object owner (the WinDbg process)
    //   (A;;GA;;;SY)    – GENERIC_ALL to SYSTEM
    //   (A;;GA;;;BA)    – GENERIC_ALL to BUILTIN\Administrators
    SECURITY_ATTRIBUTES sa = {};
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        dprintf("MCPServer: Failed to create security descriptor (error %d). Using default.\n", GetLastError());
        pSD = nullptr;
    }

    if (pSD) {
        sa.nLength              = sizeof(sa);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle       = FALSE;
    }

    // Create a new pipe instance with overlapped (async) I/O so ConnectNamedPipe
    // can be cancelled when Stop() is called.
    HANDLE hPipe = CreateNamedPipeA(
        m_pipeName.c_str(),                // Pipe name
        PIPE_ACCESS_DUPLEX |               // Read/write access
        FILE_FLAG_OVERLAPPED,              // Overlapped mode – allows cancellation
        PIPE_TYPE_MESSAGE |                // Message type pipe
        PIPE_READMODE_MESSAGE |            // Message-read mode
        PIPE_WAIT,                         // Blocking mode
        PIPE_UNLIMITED_INSTANCES,          // Max instances
        BUFFER_SIZE,                       // Output buffer size
        BUFFER_SIZE,                       // Input buffer size
        0,                                 // Default time-out
        pSD ? &sa : nullptr);              // Restricted security attributes

    if (pSD) {
        LocalFree(pSD);
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        dprintf("MCPServer: CreateNamedPipe failed with error %d\n", GetLastError());
    }

    return hPipe;
}

void MCPServer::PipeServerThread() {
    // Event used to cancel the pending ConnectNamedPipe when Stop() is called.
    HANDLE hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hStopEvent) {
        dprintf("MCPServer: Failed to create stop event, error %d\n", GetLastError());
        return;
    }
    m_stopEvent = hStopEvent;

    while (m_running) {
        // Create a pipe instance (overlapped mode)
        HANDLE hPipe = CreatePipeInstance();
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Issue an overlapped ConnectNamedPipe so we can wake up on Stop()
        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) {
            CloseHandle(hPipe);
            break;
        }

        dprintf("MCPServer: Waiting for client connection on %s\n", m_pipeName.c_str());
        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        DWORD err = GetLastError();

        if (!connected) {
            if (err == ERROR_IO_PENDING) {
                // Wait for either a client or the stop signal
                HANDLE waitHandles[2] = { ov.hEvent, hStopEvent };
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

                if (waitResult == WAIT_OBJECT_0) {
                    // ConnectNamedPipe completed – check result
                    DWORD transferred = 0;
                    connected = GetOverlappedResult(hPipe, &ov, &transferred, FALSE);
                    if (!connected) {
                        err = GetLastError();
                        if (err != ERROR_PIPE_CONNECTED) {
                            CloseHandle(ov.hEvent);
                            CloseHandle(hPipe);
                            continue;
                        }
                        connected = TRUE;
                    }
                } else {
                    // Stop was signalled – cancel pending I/O and exit
                    CancelIoEx(hPipe, &ov);
                    WaitForSingleObject(ov.hEvent, INFINITE);
                    CloseHandle(ov.hEvent);
                    CloseHandle(hPipe);
                    break;
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            } else {
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                continue;
            }
        }

        CloseHandle(ov.hEvent);

        if (connected) {
            dprintf("MCPServer: New client connected\n");

            auto client = std::make_shared<ClientConnection>(hPipe);
            client->thread = std::thread(&MCPServer::HandleClient, this, client);

            {
                std::lock_guard<std::mutex> lock(m_clientsMutex);
                m_clients.push_back(client);
            }

            CleanupDisconnectedClients();
        } else {
            CloseHandle(hPipe);
        }
    }

    CloseHandle(hStopEvent);
    m_stopEvent = NULL;

    // Clean up all clients when shutting down
    CleanupDisconnectedClients();
}

void MCPServer::CleanupDisconnectedClients() {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    
    // Check each client for active status
    auto it = m_clients.begin();
    while (it != m_clients.end()) {
        auto client = *it;
        
        if (!client->active) {
            // Client is no longer active, join thread and remove
            if (client->thread.joinable()) {
                client->thread.join();
            }
            
            it = m_clients.erase(it);
        } else {
            ++it;
        }
    }
}

void MCPServer::HandleClient(std::shared_ptr<ClientConnection> client) {
    char buffer[BUFFER_SIZE];
    DWORD bytesRead;
    std::string messageBuffer;
    
    // Keep processing until client disconnects or server stops
    while (m_running && client->active) {
        // Drain and send any queued outgoing messages (non-blocking check)
        {
            std::unique_lock<std::mutex> lock(client->queueMutex);
            while (!client->outgoingMessages.empty()) {
                json message = client->outgoingMessages.front();
                client->outgoingMessages.pop();
                lock.unlock();

                std::string messageStr = message.dump() + "\n";
                DWORD bytesWritten;
                BOOL success = WriteFile(
                    client->hPipe,
                    messageStr.c_str(),
                    (DWORD)messageStr.size(),
                    &bytesWritten,
                    NULL);

                if (!success || bytesWritten != messageStr.size()) {
                    dprintf("MCPServer: Failed to write to pipe, error %d\n", GetLastError());
                    client->active = false;
                    return;
                }
                lock.lock();
            }
        }
        
        // Check if there's data to read
        DWORD bytesAvail = 0;
        BOOL success = PeekNamedPipe(
            client->hPipe,   // Pipe handle
            NULL,            // Buffer (not needed for peek)
            0,               // Buffer size
            NULL,            // Bytes read (not needed)
            &bytesAvail,     // Bytes available
            NULL);           // Bytes left (not needed)
        
        if (!success) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                // Client disconnected
                client->active = false;
                return;
            }
            dprintf("MCPServer: PeekNamedPipe failed with error %d\n", error);
            client->active = false;
            return;
        }
        
        // If no data available, continue to process outgoing messages
        if (bytesAvail == 0) {
            continue;
        }
        
        // Read data from the pipe
        success = ReadFile(
            client->hPipe,   // Pipe handle
            buffer,          // Buffer
            BUFFER_SIZE,     // Buffer size
            &bytesRead,      // Bytes read
            NULL);           // Not overlapped
        
        if (!success || bytesRead == 0) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                // Client disconnected
                client->active = false;
                return;
            }
            dprintf("MCPServer: ReadFile failed with error %d\n", error);
            client->active = false;
            return;
        }
        
        // Append to message buffer
        messageBuffer.append(buffer, bytesRead);
        
        // Check for complete messages (terminated by newline)
        size_t pos = 0;
        while ((pos = messageBuffer.find('\n')) != std::string::npos) {
            std::string message = messageBuffer.substr(0, pos);
            messageBuffer.erase(0, pos + 1);
            
            try {
                // Parse the message as JSON
                json jsonMessage = json::parse(message);
                
                // Process the message
                json response = ProcessMessage(jsonMessage);
                
                // Send the response to this client
                std::string responseStr = response.dump() + "\n";
                DWORD bytesWritten;
                success = WriteFile(
                    client->hPipe,            // Pipe handle
                    responseStr.c_str(),      // Response buffer
                    (DWORD)responseStr.size(),// Response size
                    &bytesWritten,            // Bytes written
                    NULL);                    // Not overlapped
                
                if (!success || bytesWritten != responseStr.size()) {
                    dprintf("MCPServer: Failed to write response, error %d\n", GetLastError());
                    client->active = false;
                    return; // Disconnect on error
                }
            }
            catch (const std::exception& e) {
                dprintf("MCPServer: Error processing message: %s\n", e.what());
                
                // Send error response
                json errorResponse = {
                    {"type", "error"},
                    {"error_code", "invalid_message"},
                    {"error_message", std::string("Error processing message: ") + e.what()}
                };
                
                std::string errorStr = errorResponse.dump() + "\n";
                DWORD bytesWritten;
                WriteFile(
                    client->hPipe,          // Pipe handle
                    errorStr.c_str(),       // Error buffer
                    (DWORD)errorStr.size(), // Error size
                    &bytesWritten,          // Bytes written
                    NULL);                  // Not overlapped
            }
        }
    }
    
    // Mark client as inactive when exiting
    client->active = false;
    dprintf("MCPServer: Client handler thread exiting\n");
}

json MCPServer::ProcessMessage(const json& message) {
    // Extract message fields
    std::string messageType = message.value("type", "");
    
    if (messageType != "command") {
        // Only command messages are supported for now
        return {
            {"id", message.value("id", 0)},
            {"type", "error"},
            {"error_code", "invalid_message_type"},
            {"error_message", "Only command messages are supported"}
        };
    }
    
    std::string command = message.value("command", "");
    int id = message.value("id", 0);
    
    // Check if we have a handler for this command
    auto handlerIt = m_handlers.find(command);
    if (handlerIt == m_handlers.end()) {
        // No handler found
        return {
            {"id", id},
            {"type", "error"},
            {"error_code", "invalid_command"},
            {"error_message", "Unknown command: " + command}
        };
    }
    
    try {
        // Execute the command handler
        json response = handlerIt->second(message);
        
        // Make sure the response has the correct ID and command
        response["id"] = id;
        response["command"] = command;
        
        return response;
    }
    catch (const std::exception& e) {
        // Command execution failed
        return {
            {"id", id},
            {"type", "error"},
            {"error_code", "command_failed"},
            {"error_message", std::string("Command execution failed: ") + e.what()}
        };
    }
} 