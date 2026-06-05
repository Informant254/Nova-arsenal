#!/bin/bash
# Install core dependencies safely if needed
if [ -f /data/data/com.termux/files/usr/bin/pkg ]; then
    # Auto-optimize for Termux users to allow sound processing natively
    if ! command -v mpv &> /dev/null; then
        echo "[*] Optional component 'mpv' missing. Setting up audio driver engine..."
        pkg install mpv -y
    fi
fi

chmod +x nova_welcome.py
python3 nova_welcome.py
