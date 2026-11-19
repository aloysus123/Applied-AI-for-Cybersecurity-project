import os
import subprocess

def ping_host(host):
    # Insecure command execution with shell=True
    command = f"ping -c 1 {host}"
    return subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

if __name__ == "__main__":
    ping_host("127.0.0.1; whoami")
