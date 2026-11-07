# HTTPdis 0.7.1

The built-in HTTP and JSON listeners now request a TCP backlog of 128.
Set `listen_backlog` in the server options to override it for one listener.
Existing custom server factories keep their constructor and receive the new option.
