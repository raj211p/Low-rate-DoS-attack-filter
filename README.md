This tool is a C++ network filter that captures TCP traffic and monitors the resource usage of Apache on Linux servers. It is currently a PoC and runs on Linux.
The main module (check_connections.cpp) launches the other modules as separate threads.
Compilation requires the following flags: --lpcap (for libpcap) and --thread (for the 'thread' macro).
