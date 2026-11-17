import subprocess
import tempfile
import os
import shutil
from typing import Dict, Any

IMAGE_NAME = "crypto-sandbox:latest"

class DockerCryptoSandbox:
    """Executes Python and SageMath exploit scripts inside Docker with native fallback."""

    def __init__(self, image: str = IMAGE_NAME, memory_limit: str = "1g", timeout: int = 30):
        self.image = image
        self.memory_limit = memory_limit
        self.timeout = timeout
        self.has_docker = shutil.which("docker") is not None

    def execute(self, code: str, is_sage: bool = False, allow_network: bool = False) -> Dict[str, Any]:
        """
        Runs code inside an ephemeral container if Docker is present,
        otherwise falls back to native execution.
        """
        ext = ".sage" if is_sage else ".py"
        with tempfile.NamedTemporaryFile(suffix=ext, mode="w", delete=False, encoding="utf-8") as f:
            f.write(code)
            temp_path = f.name
        workdir = os.path.dirname(temp_path)
        copied_files = []

        # Copy challenge files from inputs/ into workdir so exploit can access them by relative filename
        inputs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")
        if os.path.exists(inputs_dir) and os.path.isdir(inputs_dir):
            for item in os.listdir(inputs_dir):
                s = os.path.join(inputs_dir, item)
                d = os.path.join(workdir, item)
                if os.path.isfile(s) and not os.path.exists(d):
                    try:
                        shutil.copy2(s, d)
                        copied_files.append(d)
                    except Exception:
                        pass

        try:
            if not self.has_docker:
                # Fallback to host environment execution with UTF-8 encoding
                has_sage_native = shutil.which("sage") is not None
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
