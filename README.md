# tcpdump-extract
A simple Python script for extracting the unique hosts from the output of tcpdump.

Pipe the output of tcpdump to the script's stdin.

By default only unique hosts are reported but if you'd like to see all (host, port)
pairs, give the script the '-p' option as the only command line argument.
