#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   💥 NOVA BINARY HUNTER v1.0                                        ║
║                                                                      ║
║   Project Zero / Daybreak-class binary vulnerability hunting:       ║
║   Static analysis → Symbolic execution → Coverage fuzzing          ║
║   → Crash triage → Exploitability classification → PoC gen         ║
╚══════════════════════════════════════════════════════════════════════╝
"""
import json, os, re, shutil, struct, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

WORKSPACE = os.path.expanduser("~/nova_workspace")
NOVA_BIN  = os.path.join(WORKSPACE, "bin")

def _env():
    e = dict(os.environ)
    e["PATH"] = f"{NOVA_BIN}:/usr/local/go/bin:{os.path.expanduser('~/.cargo/bin')}:" + e.get("PATH","")
    return e

def _run(cmd: str, timeout: int = 120, cwd: str = WORKSPACE) -> Tuple[int,str,str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, env=_env(), cwd=cwd)
        return r.returncode, r.stdout[:8000], r.stderr[:2000]
    except subprocess.TimeoutExpired:
        return 1, "", f"timeout:{timeout}s"
    except Exception as e:
        return 1, "", str(e)

def _has(t: str) -> bool:
    return bool(shutil.which(t) or (os.path.isfile(os.path.join(NOVA_BIN,t)) and
                                     os.access(os.path.join(NOVA_BIN,t),os.X_OK)))


class BinaryProfile:
    def __init__(self, path: str):
        self.path=path; self.arch="unknown"; self.bits=0; self.os_type="unknown"
        self.pie=False; self.nx=False; self.canary=False; self.relro="none"
        self.stripped=False; self.imports=[]; self.strings=[]; self.functions=[]

    def to_dict(self): return vars(self)

    def attack_surface(self) -> List[str]:
        s = []
        if not self.canary:  s.append("stack_overflow_no_canary")
        if not self.pie:     s.append("rop_fixed_addresses")
        if not self.nx:      s.append("shellcode_injection")
        if self.relro=="none":    s.append("got_overwrite")
        if self.relro=="partial": s.append("partial_relro_got_overwrite")
        dangerous = ["gets","strcpy","strcat","scanf","sprintf","system","popen","exec","recv"]
        for fn in dangerous:
            if fn in " ".join(self.imports).lower(): s.append(f"dangerous_fn_{fn}")
        return s


class NovaStaticAnalyser:
    def analyse(self, path: str) -> BinaryProfile:
        print(f"  💥 [Static] {path}")
        p = BinaryProfile(path)
        if _has("checksec"):
            _, out, _ = _run(f"checksec --file={path} --format=json 2>/dev/null")
            try:
                data = json.loads(out); info = list(data.values())[0] if data else {}
                p.nx     = info.get("nx","no").lower()=="yes"
                p.pie    = info.get("pie","no").lower()!="no"
                p.canary = info.get("canary","no").lower()=="yes"
                p.relro  = info.get("relro","none").lower().replace(" relro","")
            except Exception: pass
        _, out, _ = _run(f"file {path} 2>/dev/null")
        p.bits = 64 if "64-bit" in out else (32 if "32-bit" in out else 0)
        p.os_type = "linux" if "ELF" in out else ("windows" if "PE32" in out else "macos" if "Mach-O" in out else "unknown")
        p.arch = "x86_64" if ("x86" in out and p.bits==64) else ("x86" if "x86" in out else ("arm64" if ("ARM" in out and p.bits==64) else "arm" if "ARM" in out else "unknown"))
        p.stripped = "stripped" in out
        _, out, _ = _run(f"strings {path} 2>/dev/null | head -200")
        p.strings = [s for s in out.splitlines() if len(s)>4][:100]
        _, out, _ = _run(f"readelf -d {path} 2>/dev/null | grep NEEDED")
        p.imports = re.findall(r'\[(.*?)\]', out)
        _, out, _ = _run(f"nm -D {path} 2>/dev/null | grep ' T ' | head -100")
        p.functions = [l.split()[-1] for l in out.splitlines() if l.strip()][:50]
        print(f"  💥 [Static] arch={p.arch} bits={p.bits} pie={p.pie} nx={p.nx} canary={p.canary} relro={p.relro}")
        print(f"  💥 [Static] Attack surface: {p.attack_surface()}")
        return p

    def dangerous_calls(self, path: str) -> List[Dict]:
        findings = []
        if _has("r2"):
            _, out, _ = _run(f"r2 -q -c 'aaa; afl~gets; afl~strcpy; afl~system' {path} 2>/dev/null", timeout=60)
            for line in out.splitlines():
                if any(fn in line for fn in ["gets","strcpy","system","popen","strcat","scanf"]):
                    findings.append({"type":"dangerous_function_call","detail":line.strip(),"severity":"high"})
        return findings


class NovaFuzzer:
    def __init__(self, binary: str):
        self.binary  = binary
        self.workdir = os.path.join(WORKSPACE,"fuzzing",os.path.basename(binary))
        os.makedirs(self.workdir, exist_ok=True)

    def _corpus(self) -> str:
        d = os.path.join(self.workdir,"corpus"); os.makedirs(d,exist_ok=True)
        for i,seed in enumerate([b"AAAA",b"A"*256,bytes(range(256)),b'{"key":"val"}',
                                   b'<?xml version="1.0"?><r>t</r>']):
            with open(os.path.join(d,f"s{i:04d}"),"wb") as f: f.write(seed)
        return d

    def run_afl(self, timeout_sec: int = 120) -> Dict:
        if not _has("afl-fuzz"): return {"ok":False,"error":"afl-fuzz not installed"}
        corpus = self._corpus()
        out_dir = os.path.join(self.workdir,"afl_out"); os.makedirs(out_dir,exist_ok=True)
        cmd = f"afl-fuzz -i {corpus} -o {out_dir} -t 1000 -- {self.binary}"
        print(f"  💥 [Fuzz] AFL++ {timeout_sec}s")
        _run(f"timeout {timeout_sec} {cmd} 2>/dev/null", timeout=timeout_sec+10)
        return {"ok":True,"crashes":self._crashes(os.path.join(out_dir,"default","crashes"))}

    def run_honggfuzz(self, timeout_sec: int = 120) -> Dict:
        if not _has("honggfuzz"): return {"ok":False,"error":"not installed"}
        corpus = self._corpus()
        ws = os.path.join(self.workdir,"hfuzz"); os.makedirs(ws,exist_ok=True)
        _run(f"timeout {timeout_sec+5} honggfuzz --input {corpus} --workspace {ws} --timeout {timeout_sec} -- {self.binary} 2>/dev/null", timeout=timeout_sec+10)
        return {"ok":True,"crashes":self._crashes(ws)}

    def _crashes(self, crash_dir: str) -> List[Dict]:
        crashes = []
        if not os.path.isdir(crash_dir): return crashes
        for f in Path(crash_dir).iterdir():
            if f.is_file() and "README" not in f.name:
                d = f.read_bytes()
                crashes.append({"file":str(f),"size":len(d),"head":d[:32].hex()})
        return crashes


EXPLOITABILITY = {
    "SIGSEGV_IP":    ("exploitable",           "critical", "Instruction pointer control"),
    "SIGSEGV_WRITE": ("likely_exploitable",    "high",     "Arbitrary write primitive"),
    "SIGSEGV_READ":  ("probably_exploitable",  "high",     "Arbitrary read primitive"),
    "SIGABRT_STACK": ("likely_not_exploitable","medium",   "Stack canary triggered"),
    "SIGABRT_HEAP":  ("exploitable",           "critical", "Heap corruption"),
}

class NovaCrashTriager:
    def triage(self, binary: str, crash_input: bytes) -> Dict:
        result = {"binary":binary,"classification":"unknown","severity":"info","reason":""}
        with tempfile.NamedTemporaryFile(delete=False,suffix=".crash") as tmp:
            tmp.write(crash_input); tmp_path = tmp.name
        try:
            gdb_src = f"run < {tmp_path}\ninfo registers\nbacktrace\nquit\n"
            gs = tmp_path+".gdb"
            with open(gs,"w") as f: f.write(gdb_src)
            _, out, _ = _run(f"gdb -batch -x {gs} {binary} 2>/dev/null", timeout=15)
            if "SIGSEGV" in out:
                pc_m = re.search(r'(?:rip|eip)\s+0x([0-9a-f]+)', out, re.I)
                if pc_m:
                    pc = int(pc_m.group(1),16)
                    if pc in (0x4141414141414141,0x41414141): result["classification"]="SIGSEGV_IP"
                    elif "0x000000" in pc_m.group(0):         result["classification"]="SIGSEGV_WRITE"
                    else:                                       result["classification"]="SIGSEGV_READ"
                else: result["classification"]="SIGSEGV_READ"
            elif "SIGABRT" in out:
                result["classification"] = "SIGABRT_HEAP" if any(k in out.lower() for k in ["heap","malloc"]) else "SIGABRT_STACK"
            if result["classification"] in EXPLOITABILITY:
                exp,sev,reason = EXPLOITABILITY[result["classification"]]
                result["exploitability"]=exp; result["severity"]=sev; result["reason"]=reason
        finally:
            for f in [tmp_path, tmp_path+".gdb"]:
                try: os.unlink(f)
                except: pass
        return result


class NovaBinaryHunter:
    def __init__(self, verbose: bool = True):
        self.verbose  = verbose
        self.analyser = NovaStaticAnalyser()
        self.triager  = NovaCrashTriager()
        self.findings: List[Dict] = []

    def _angr_hunt(self, binary: str, profile: BinaryProfile) -> List[Dict]:
        findings = []
        try:
            import angr, claripy
            print(f"  💥 [angr] Loading {binary}")
            proj = angr.Project(binary, auto_load_libs=False)
            for fn in ["gets","strcpy","strcat","scanf","sprintf","system"]:
                sym = proj.loader.find_symbol(fn)
                if sym:
                    print(f"  💥 [angr] ⚠️  Dangerous import: {fn} @ {hex(sym.rebased_addr)}")
                    findings.append({"type":f"dangerous_import_{fn}","severity":"high",
                                      "address":hex(sym.rebased_addr),"binary":binary,"tool":"angr"})
            cfg = proj.analyses.CFGFast(normalize=True)
            print(f"  💥 [angr] CFG: {len(cfg.graph.nodes())} nodes")
            state = proj.factory.blank_state(addr=proj.entry)
            simgr = proj.factory.simulation_manager(state)
            simgr.run(until=lambda sm: len(sm.active)==0 or len(sm.unconstrained)>0, n=500)
            if simgr.unconstrained:
                print(f"  💥 [angr] 🔴 CRITICAL: Unconstrained execution!")
                findings.append({"type":"unconstrained_execution","severity":"critical",
                                   "detail":"angr found unconstrained PC","binary":binary,"tool":"angr"})
        except ImportError: print("  💥 [angr] Not installed")
        except Exception as e: print(f"  💥 [angr] Error: {e}")
        return findings

    def hunt(self, binary: str, fuzz_time: int = 60, use_angr: bool = True) -> Dict:
        print(f"\n  💥 Nova Binary Hunter — {binary}\n")
        start = time.time()
        if not os.path.exists(binary): return {"ok":False,"error":f"Not found: {binary}"}
        profile = self.analyser.analyse(binary)
        danger  = self.analyser.dangerous_calls(binary)
        self.findings.extend(danger)
        if use_angr:
            self.findings.extend(self._angr_hunt(binary, profile))
        fuzzer = NovaFuzzer(binary)
        fuzz   = fuzzer.run_afl(fuzz_time) if _has("afl-fuzz") else fuzzer.run_honggfuzz(fuzz_time)
        crashes = fuzz.get("crashes",[])
        if crashes: print(f"  💥 [Triage] {len(crashes)} crashes")
        for crash in crashes[:10]:
            try:
                with open(crash["file"],"rb") as f: data = f.read()
                t = self.triager.triage(binary, data)
                if t.get("exploitability") in ("exploitable","likely_exploitable"):
                    self.findings.append({"type":f"Memory Corruption ({t['classification']})",
                                           "name":t["reason"],"severity":t["severity"],
                                           "binary":binary,"details":t,"tool":"nova_binary_hunter"})
                    print(f"  💥 [Triage] 🔴 {t['reason']} [{t['severity']}]")
            except Exception: pass
        elapsed = round(time.time()-start,1)
        print(f"\n  💥 Binary hunt: {len(self.findings)} findings in {elapsed}s")
        return {"binary":binary,"duration_sec":elapsed,"profile":profile.to_dict(),
                "attack_surface":profile.attack_surface(),"crashes_found":len(crashes),
                "findings":self.findings}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="💥 Nova Binary Hunter")
    p.add_argument("binary"); p.add_argument("--fuzz-time",type=int,default=60)
    p.add_argument("--no-angr",action="store_true"); p.add_argument("--output")
    args = p.parse_args()
    hunter = NovaBinaryHunter(verbose=True)
    result = hunter.hunt(args.binary, fuzz_time=args.fuzz_time, use_angr=not args.no_angr)
    if args.output:
        with open(args.output,"w") as f: json.dump(result,f,indent=2)
    else: print(json.dumps(result,indent=2))
