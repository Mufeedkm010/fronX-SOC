import subprocess

print("Starting journal test...")

process = subprocess.Popen(
    ["journalctl", "-u", "ssh", "-f", "--no-pager", "-o", "cat"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

print("Waiting for SSH logs...\n")

for line in iter(process.stdout.readline, ''):
    print("LOG:", line.strip())
