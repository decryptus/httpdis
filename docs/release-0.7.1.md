# HTTPdis 0.7.1

The built-in HTTP and JSON servers now request a TCP listen backlog of 128.
Set the integer option `listen_backlog` before initializing a context to override
it for that listener. For example, use 5 to keep the previous Python 3.12 default.
Custom server factories continue to receive the options and manage their sockets.
