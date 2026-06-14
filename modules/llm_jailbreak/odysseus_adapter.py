"""
Nova Arsenal — Odysseus Adapter
Wraps the Odysseus dual-steganography LLM jailbreak framework.
Odysseus hides adversarial payloads inside innocuous image perturbations,
bypassing multimodal LLM safety filters. NDSS 2026.

Source: cloned_repos/Odysseus/
"""

import sys
import subprocess
from pathlib import Path
from typing import Optional, List


ODYSSEUS_REPO = Path(__file__).parents[3] / "cloned_repos" / "Odysseus"


class OdysseusAdapter:
    """
    Adapter for the Odysseus dual-steganography jailbreak.
    Embeds adversarial triggers into images using encoder/decoder model pairs,
    then submits the carrier image alongside a benign prompt to bypass
    multimodal safety classifiers.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self.root = repo_root or ODYSSEUS_REPO
        self.available = self.root.exists()
        self.data_dir  = self.root / "data"
        self.model_dir = self.root / "model"

    def check_setup(self) -> bool:
        if not self.available:
            print(f"[!] Odysseus not found at {self.root}")
            return False
        required = ["main.py", "__init__.py", "model/encoder.py", "model/decoder.py"]
        missing = [r for r in required if not (self.root / r).exists()]
        if missing:
            print(f"[!] Missing Odysseus components: {missing}")
            return False
        return True

    def list_benchmarks(self):
        """List available jailbreak benchmark datasets."""
        print("\n[*] Available Benchmark Datasets:\n")
        if self.data_dir.exists():
            for f in self.data_dir.glob("*.txt"):
                lines = f.read_text().strip().splitlines()
                print(f"  • {f.name} — {len(lines)} prompts")
        else:
            print("  [!] data/ directory not found")

    def encode_payload(self, carrier_image: str, payload: str, output_path: str = "stego_output.png"):
        """
        Encode an adversarial payload into a carrier image using Odysseus encoder.
        The result is visually imperceptible to humans but triggers the target model.
        """
        if not self.check_setup():
            return None

        print(f"\n[*] Odysseus Encoder")
        print(f"    Carrier:  {carrier_image}")
        print(f"    Payload:  {payload[:60]}{'...' if len(payload)>60 else ''}")
        print(f"    Output:   {output_path}\n")

        cmd = [
            sys.executable, str(self.root / "main.py"),
            "--mode", "encode",
            "--image", carrier_image,
            "--payload", payload,
            "--output", output_path,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.root), timeout=60)
            if result.returncode == 0:
                print(f"[+] Stego image written: {output_path}")
                return output_path
            else:
                print(f"[!] Encoder failed:\n{result.stderr[:400]}")
        except Exception as e:
            print(f"[!] Odysseus encode error: {e}")
        return None

    def run_benchmark(self, dataset: str = "JailbreakBench.txt", model: str = "gpt-4o"):
        """
        Run Odysseus against a benchmark dataset on a target model.
        """
        if not self.check_setup():
            return

        dataset_path = self.data_dir / dataset
        if not dataset_path.exists():
            print(f"[!] Dataset not found: {dataset_path}")
            self.list_benchmarks()
            return

        print(f"\n[*] Odysseus Benchmark Run")
        print(f"    Dataset: {dataset} ({len(dataset_path.read_text().splitlines())} prompts)")
        print(f"    Target:  {model}\n")

        cmd = [
            sys.executable, str(self.root / "main.py"),
            "--mode", "attack",
            "--dataset", str(dataset_path),
            "--model", model,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.root), timeout=300)
            print(result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout)
            if result.returncode != 0:
                print(f"[!] stderr:\n{result.stderr[:400]}")
        except subprocess.TimeoutExpired:
            print("[!] Benchmark timeout (>5 min)")
        except Exception as e:
            print(f"[!] Odysseus run error: {e}")
