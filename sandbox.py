import subprocess
import tempfile
import os
import shutil
import json
import urllib.request
import urllib.parse
from typing import Dict, Any

IMAGE_NAME = "crypto-sandbox:latest"
SAGEMATH_CELL_URL = os.getenv("SAGEMATH_CELL_URL", "https://sagecell.sagemath.org/service")

class DockerCryptoSandbox:
    """Executes Python and SageMath exploit scripts inside Docker with native, WSL, and SageMathCell fallback."""

    def __init__(self, image: str = IMAGE_NAME, memory_limit: str = "1g", timeout: int = 30):
        self.image = image
        self.memory_limit = memory_limit
        self.timeout = timeout
        self.has_docker = shutil.which("docker") is not None
        self._has_wsl_sage = None

    def check_wsl_sage(self) -> bool:
        """Checks if WSL is installed and has SageMath executable."""
        if self._has_wsl_sage is not None:
            return self._has_wsl_sage
        if shutil.which("wsl") is None:
            self._has_wsl_sage = False
            return False
        try:
            res = subprocess.run(["wsl", "which", "sage"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            self._has_wsl_sage = (res.returncode == 0 and b"sage" in res.stdout)
        except Exception:
            self._has_wsl_sage = False
        return self._has_wsl_sage

    def execute_via_sagecell(self, code: str) -> Dict[str, Any]:
        """
        Executes SageMath code via the public or self-hosted SageMathCell API service.
        Useful on Windows when Docker and WSL are not installed.
        """
        try:
            payload = urllib.parse.urlencode({"code": code}).encode("utf-8")
            req = urllib.request.Request(
                SAGEMATH_CELL_URL,
                data=payload,
                headers={"User-Agent": "Crypto-CTF-Agent/1.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                stdout = data.get("stdout", "")
                stderr = data.get("stderr", "")
                success = data.get("success", True)
                return {
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": 0 if success else 1,
                    "timed_out": False
                }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": f"SageMathCell API execution failed: {e}",
                "exit_code": -1,
                "timed_out": False
            }

    def execute(self, code: str, is_sage: bool = False, allow_network: bool = False, job_id: str = None) -> Dict[str, Any]:
        """
        Runs code inside an ephemeral container if Docker is present,
        otherwise falls back to WSL, SageMathCell, or native execution.
        Isolates input challenge files per job_id to prevent cross-job IDOR.
        """
        ext = ".sage" if is_sage else ".py"
        with tempfile.NamedTemporaryFile(suffix=ext, mode="w", delete=False, encoding="utf-8") as f:
            f.write(code)
            temp_path = f.name
        workdir = os.path.dirname(temp_path)
        copied_files = []

        # Copy challenge files from inputs/<job_id> or inputs/ into workdir so exploit can access them by relative filename
        inputs_base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")
        candidate_dirs = []
        if job_id:
            job_specific_dir = os.path.join(inputs_base, job_id)
            if os.path.exists(job_specific_dir) and os.path.isdir(job_specific_dir):
                candidate_dirs.append(job_specific_dir)
        if os.path.exists(inputs_base) and os.path.isdir(inputs_base):
            candidate_dirs.append(inputs_base)

        for inputs_dir in candidate_dirs:
            for item in os.listdir(inputs_dir):
                s = os.path.join(inputs_dir, item)
                if os.path.isfile(s) and not item.startswith("."):
                    # Strip 16-hex prefix if storage name is '{hex16}_{filename}' to give exploit original filename
                    clean_item = item.split("_", 1)[1] if ("_" in item and len(item.split("_", 1)[0]) == 16) else item
                    d = os.path.join(workdir, clean_item)
                    if not os.path.exists(d):
                        try:
                            shutil.copy2(s, d)
                            copied_files.append(d)
                        except Exception:
                            pass

        try:
            # 1. Fallback to WSL SageMath if is_sage and Docker is unavailable
            if not self.has_docker:
                has_sage_native = shutil.which("sage") is not None
                if is_sage and not has_sage_native and self.check_wsl_sage():
                    # Execute via WSL
                    wsl_path = subprocess.run(["wsl", "wslpath", "-u", temp_path], stdout=subprocess.PIPE, text=True).stdout.strip()
                    res = subprocess.run(
                        ["wsl", "sage", wsl_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=self.timeout
                    )
                    return {
                        "stdout": res.stdout,
                        "stderr": res.stderr,
                        "exit_code": res.returncode,
                        "timed_out": False
                    }

                # 2. Fallback to SageMathCell API if is_sage and neither native nor WSL sage is available
                if is_sage and not has_sage_native:
                    sagecell_res = self.execute_sagecell(code)
                    if sagecell_res.get("exit_code") == 0 or sagecell_res.get("stdout"):
                        return sagecell_res

                # 3. Native host Python or Sage execution
                runner = "sage" if (is_sage and has_sage_native) else "python"

                env = os.environ.copy()
                env["PYTHONIOENCODING"] = "utf-8"
                res = subprocess.run(
                    [runner, temp_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout,
                    env=env,
                    encoding="utf-8",
                    errors="replace",
                    cwd=workdir
                )

                stderr_out = res.stderr
                # If execution failed because SageMath was attempted on Python
                if res.returncode != 0 and ("no module named 'sage'" in stderr_out.lower() or "import sage" in code.lower()):
                    stderr_out = (
                        "ModuleNotFoundError: No module named 'sage'. SageMath and Docker are NOT available on this system. "
                        "You MUST write standard Python 3 code using gmpy2, sympy, pycryptodome, or rsa_cryptanalysis without 'import sage'."
                    )

                return {
                    "stdout": res.stdout,
                    "stderr": stderr_out,
                    "exit_code": res.returncode,
                    "timed_out": False
                }

            # 4. Standard Docker sandbox execution
            filename = os.path.basename(temp_path)

            net_flag = "--network=host" if allow_network else "--network=none"
            runner_cmd = "sage" if is_sage else "python3"

            cmd = [
                "docker", "run", "--rm",
                net_flag,
                f"--memory={self.memory_limit}",
                "--cpus=1.5",
                "-v", f"{workdir}:/sandbox",
                "-w", "/sandbox",
                self.image,
                runner_cmd, filename
            ]

            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout
            )
            return {
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.returncode,
                "timed_out": False
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Execution timed out after {self.timeout}s",
                "exit_code": -1,
                "timed_out": True
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "timed_out": False
            }
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            for fpath in copied_files:
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
