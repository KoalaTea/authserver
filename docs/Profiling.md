# Performance Profiling
AuthServer supports built in performance monitoring and debugging via the Golang pprof tool developed by Google. To run AuthServer with profiling enabled, ensure the config has enable_pprof=true.

## Install Graphviz
Ensure you have an updated version of Graphviz installed for visualizing profile outputs.

apt install -y graphviz

## Collect a Profile
Start AuthServer with profiling enabled: go run ./server.
Collect a Profile in desired format (e.g. png): go tool pprof -png -seconds=10 http://127.0.0.1:80/debug/pprof/allocs?seconds=10 > .pprof/allocs.png
a. Replace “allocs” with the name of the profile to collect.
b. Replace the value of seconds with the amount of time you need to reproduce performance issues.
c. Read more about the available profiling URL parameters here. d. go tool pprof does not need to run on the same host as AuthServer, just ensure you provide the correct HTTP url in the command. Note that Graphviz must be installed on the system you’re running pprof from.
Reproduce any interactions with AuthServer that you’d like to collect profiling information for.

A graph visualization of the requested performance profile should now be saved locally, take a look and see what’s going on