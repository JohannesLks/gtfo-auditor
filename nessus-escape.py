import sys
import os

if len(sys.argv) != 2:
    print("Usage: python3 escape_for_nessus.py <input_file>")
    sys.exit(1)

input_path = sys.argv[1]
if not os.path.isfile(input_path):
    print(f"File not found: {input_path}")
    sys.exit(1)

# Ziel-Dateiname
base_name = os.path.basename(input_path)
name, ext = os.path.splitext(base_name)
output_path = f"{name}_nessus_escaped{ext}"

with open(input_path, "r", encoding="utf-8") as infile:
    lines = infile.readlines()

escaped_lines = []
for line in lines:
    # Schritt 1: bestehende \" doppelt escapen → \\\" (aber nur echte Backslashes)
    line = line.replace(r'\"', r'\\\"')
    # Schritt 2: normale " escapen
    line = line.replace('"', r'\"')
    # Schritt 3: ausgeschriebene \n (Backslash + n) zu \\n
    line = line.replace(r'\n', r'\\n')
    escaped_lines.append(line)

with open(output_path, "w", encoding="utf-8") as outfile:
    outfile.writelines(escaped_lines)

print(f"[+] Escaped version written to: {output_path}")
