"""Opt-in Windows SYSTEM coordinator guard; never a scientific Job profile.

Reads the administrator's atomic runtime pointer, owns only its newly launched
local process tree, preserves intentional stop across task/watchdog triggers,
and persists a bounded retry budget. Installation/authority cutover is separate.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from types import SimpleNamespace
import uuid

from .origin_transfer import managed_path
from .release_maintenance import request_cooperative_shutdown


class SuspendedProcessTree:
    """Assign the Job Object *before* Python's Windows launcher can fork.

    In particular, assigning a regular Popen after creation would race with
    the venv launcher creating its real interpreter. No PID enumeration or
    global name-based killing is used here.
    """

    def __init__(self, command, *, cwd, env, stdout, stderr):
        if os.name != "nt":
            raise RuntimeError("Windows process-tree guard required")
        import _winapi
        import ctypes
        from ctypes import wintypes
        import msvcrt
        from .remote_agent.windows_job import ProcessTreeGuard

        self.handle = None
        self.guard = None
        self.pid = None
        thread = None
        try:
            with open(os.devnull, "rb") as input_file, open(stdout, "ab", buffering=0) as out, open(stderr, "ab", buffering=0) as err:
                handles = [msvcrt.get_osfhandle(f.fileno()) for f in (input_file, out, err)]
                for handle in handles:
                    os.set_handle_inheritable(handle, True)
                startup = subprocess.STARTUPINFO()
                startup.dwFlags = subprocess.STARTF_USESTDHANDLES
                startup.hStdInput, startup.hStdOutput, startup.hStdError = handles
                startup.lpAttributeList = {"handle_list": handles}
                self.handle, thread, self.pid, _ = _winapi.CreateProcess(
                    str(command[0]), subprocess.list2cmdline([str(x) for x in command]),
                    None, None, True, 0x00000004 | subprocess.CREATE_NO_WINDOW,
                    env, str(cwd), startup,
                )
                self.guard = ProcessTreeGuard(SimpleNamespace(_handle=self.handle, pid=self.pid))
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.ResumeThread.argtypes = [wintypes.HANDLE]
                kernel.ResumeThread.restype = wintypes.DWORD
                if kernel.ResumeThread(thread) == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            try:
                if self.handle is not None and self.poll() is None:
                    _winapi.TerminateProcess(self.handle, 1)
            finally:
                self.close(force=True)
            raise
        finally:
            if thread is not None:
                _winapi.CloseHandle(thread)

    def poll(self):
        import _winapi
        if _winapi.WaitForSingleObject(self.handle, 0) == _winapi.WAIT_TIMEOUT:
            return None
        return _winapi.GetExitCodeProcess(self.handle)

    def alive(self):
        if self.poll() is None:
            return True
        # Closing a kill-on-close Job Object while descendants remain would
        # turn a normal stop into forced cleanup. Keep the ownership barrier.
        return bool(self.guard and self.guard.accounting_snapshot()["active_processes"])

    def close(self, *, force=False):
        import _winapi
        if not force and self.handle is not None and self.alive():
            raise RuntimeError("refuse to close an active coordinator Job Object without cooperative exit")
        if self.guard is not None:
            self.guard.close()
            self.guard = None
        if self.handle is not None:
            _winapi.WaitForSingleObject(self.handle, 5000)
            _winapi.CloseHandle(self.handle)
            self.handle = None


class CoordinatorGuard:
    failure_limit = 5
    cooldown_s = 600
    stable_s = 120

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path).absolute()
        raw = json.loads(self.config_path.read_text(encoding="utf-8-sig"))
        if set(raw) != {"home", "operator_identity_file", "origin_transfer", "port"}:
            raise ValueError("unsupported coordinator guard configuration")
        self.home = Path(raw["home"])
        if not self.home.is_absolute() or self.home.name != "control-plane" or self.home.parent.name != "ResearchComputeNetwork":
            raise ValueError("coordinator home must be an explicit ResearchComputeNetwork/control-plane root")
        self.startup = managed_path(self.home, "startup")
        if self.config_path != self.startup / "supervision.json":
            raise ValueError("guard configuration must be inside the protected startup root")
        self.identity = Path(raw["operator_identity_file"])
        if not self.identity.is_absolute() or not self.identity.is_file():
            raise ValueError("explicit coordinator operator identity file required")
        if type(raw["origin_transfer"]) is not bool or type(raw["port"]) is not int or not 1024 <= raw["port"] <= 65535:
            raise ValueError("invalid guarded service settings")
        self.config = raw
        self.marker = managed_path(self.startup, "coordinator.disabled")
        self.state_path = managed_path(self.startup, "supervision-state.json")
        self.lock_path = managed_path(self.startup, "supervision.lock")
        self.events = managed_path(self.startup, "supervision.events.jsonl")
        self.lock = None
        self.child = None
        self.state = self.read_state()

    def read_state(self):
        if not self.state_path.exists():
            return {"state": "not-started", "consecutive_failures": 0, "next_retry_at": 0.0}
        value = json.loads(self.state_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("invalid coordinator guard state")
        return value

    def save(self, state, **fields):
        self.state.update(fields)
        self.state.update(state=state, updated_at=time.time(), wrapper_pid=os.getpid())
        partial = self.state_path.with_name(".supervision-" + uuid.uuid4().hex + ".partial")
        try:
            partial.write_text(json.dumps(self.state), encoding="utf-8")
            os.replace(partial, self.state_path)
        finally:
            partial.unlink(missing_ok=True)

    def event(self, kind, **fields):
        # Callers pass only types/codes/PIDs, never credentials/commands/paths.
        with self.events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"at": time.time(), "event": kind, **fields}) + "\n")

    def acquire(self):
        import msvcrt
        self.lock = self.lock_path.open("a+b")
        if self.lock_path.stat().st_size == 0:
            self.lock.write(b"\0")
            self.lock.flush()
        self.lock.seek(0)
        try:
            msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.lock.close()
            self.lock = None
            return False
        return True

    def release(self):
        if self.lock is not None:
            import msvcrt
            self.lock.seek(0)
            msvcrt.locking(self.lock.fileno(), msvcrt.LK_UNLCK, 1)
            self.lock.close()
            self.lock = None

    def launch_contract(self):
        pointer_path = managed_path(self.home, "runtime/current.json")
        pointer = json.loads(pointer_path.read_text(encoding="utf-8-sig"))
        runtime, python = Path(pointer["runtime_root"]), Path(pointer["python_executable"])
        if not runtime.is_absolute() or runtime.parent != self.home / "runtime":
            raise ValueError("selected runtime is outside coordinator runtime roots")
        managed_path(self.home, "runtime/" + runtime.name + "/Scripts/python.exe")
        if python != runtime / "Scripts" / "python.exe" or not python.is_file():
            raise ValueError("selected Python is not the managed runtime interpreter")
        database = managed_path(self.home, "control-plane.db")
        if not database.is_file() or pointer["database_url"].replace("\\", "/").casefold() != ("sqlite:///" + database.as_posix()).casefold():
            raise ValueError("the migrated canonical database must exist before service activation")
        if pointer["host"] != "127.0.0.1" or pointer["port"] != self.config["port"] or pointer["require_auth"] is not True:
            raise ValueError("service must use authenticated, configured loopback endpoint")
        command = [str(python), "-m", "research_compute_network.cli", "--database-url", pointer["database_url"],
                   "serve", "--host", "127.0.0.1", "--port", str(self.config["port"]), "--require-auth"]
        for version in pointer.get("candidate_runtime_versions", []):
            if not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{24}", version):
                raise ValueError("invalid explicit candidate runtime fingerprint")
            command.extend(["--canary-runtime-version", version])
        env = dict(os.environ)
        for key in ("PYTHONPATH", "PYTHONHOME", "RCN_TOKEN"):
            env.pop(key, None)
        env.update(RCN_HOME=str(self.home), RCN_SSH_IDENTITY_FILE=str(self.identity),
                   RCN_ORIGIN_TRANSFER="1" if self.config["origin_transfer"] else "0",
                   RCN_CONTROL_PLANE_DEPLOYMENT_ID=str(pointer["deployment_id"]),
                   RCN_CONTROL_PLANE_RUNTIME_ROOT=str(runtime), RCN_CONTROL_PLANE_PYTHON_EXECUTABLE=str(python))
        return command, runtime, env

    def wait_enabled(self, until):
        while time.time() < until:
            if self.marker.exists():
                return False
            time.sleep(min(0.5, max(0, until - time.time())))
        return not self.marker.exists()

    def run(self):
        if not self.acquire():
            return 0
        try:
            while not self.marker.exists():
                if not self.wait_enabled(float(self.state.get("next_retry_at", 0))):
                    break
                if int(self.state.get("consecutive_failures", 0)) >= self.failure_limit:
                    self.state["consecutive_failures"] = 0
                try:
                    command, runtime, env = self.launch_contract()
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    self.marker.write_text("configuration-needs-operator-review", encoding="utf-8")
                    self.save("blocked-configuration", error_type=type(exc).__name__, child_pid=None)
                    self.event("configuration_blocked", error_type=type(exc).__name__)
                    return 0
                failures = int(self.state.get("consecutive_failures", 0)) + 1
                # Save budget before launch so a wrapper crash cannot reset it.
                self.save("launching", consecutive_failures=failures, next_retry_at=time.time() + self.cooldown_s,
                          child_pid=None, cooperative_shutdown_protocol="cooperative-guard-v1")
                started = time.monotonic()
                generation = str(uuid.uuid4())
                env["RCN_COORDINATOR_GENERATION"] = generation
                env["RCN_COOPERATIVE_SHUTDOWN"] = "1"
                logs = managed_path(self.startup, "service-logs")
                logs.mkdir(exist_ok=True)
                try:
                    self.child = SuspendedProcessTree(command, cwd=runtime, env=env,
                        stdout=logs / (generation + ".stdout.log"), stderr=logs / (generation + ".stderr.log"))
                    self.save("process-running-health-unverified", child_pid=self.child.pid, generation=generation)
                    self.event("child_started", child_pid=self.child.pid)
                    while self.child.poll() is None and not self.marker.exists():
                        if time.monotonic() - started >= self.stable_s:
                            failures = 0
                        self.save("process-running-health-unverified", child_pid=self.child.pid,
                                  consecutive_failures=failures,
                                  next_retry_at=time.time() + self.cooldown_s if failures >= self.failure_limit else 0.0)
                        time.sleep(1)
                    if self.marker.exists():
                        self.cooperative_stop_child(generation=generation)
                    code = self.child.poll()
                    self.event("child_exited" if code is not None else "intentional_stop", exit_code=code)
                except OSError as exc:
                    self.event("launch_failed", error_type=type(exc).__name__, winerror=getattr(exc, "winerror", None))
                finally:
                    if self.child is not None:
                        self.cooperative_stop_child(generation=generation)
                        self.child.close()
                        self.child = None
                if self.marker.exists():
                    break
                delay = self.cooldown_s if failures >= self.failure_limit else min(60, 2 ** max(1, failures))
                self.save("retry-cooldown" if failures >= self.failure_limit else "restart-backoff",
                          child_pid=None, next_retry_at=time.time() + delay, consecutive_failures=failures)
            self.save("intentionally-stopped", child_pid=None, next_retry_at=0.0)
            return 0
        finally:
            if self.child is not None:
                self.cooperative_stop_child(generation=generation)
                self.child.close()
            self.release()

    def stop(self, *, timeout=30):
        self.marker.write_text("intentional-stop", encoding="utf-8")
        self.event("operator_stop_requested")
        deadline = time.monotonic() + timeout
        while not self.acquire():
            if time.monotonic() >= deadline:
                raise TimeoutError("coordinator guard did not finish its scoped stop")
            time.sleep(0.25)
        self.release()

    def cooperative_stop_child(self, *, generation, timeout=30):
        """Normal maintenance never escalates to Job Object termination.

        The fixed local IPC is consumed by the CLI's uvicorn shutdown hook.
        If it is unavailable or the API needs longer, retain ownership and
        evidence while waiting. The requesting stop command times out safely.
        """
        def alive():
            try:
                return self.child is not None and (
                    self.child.alive() if hasattr(self.child, "alive") else self.child.poll() is None)
            except OSError:
                return True  # missing accounting is not authority to force-close
        if not alive():
            return
        operation_id = str(uuid.uuid4())
        sent = False
        deadline = time.monotonic() + max(0, timeout)
        deferred = False
        while alive():
            if not sent:
                try:
                    request_cooperative_shutdown(self.home, child_pid=self.child.pid,
                        process_created=0.0, generation=generation, operation_id=operation_id)
                    self.save("cooperative-stop-pending", child_pid=self.child.pid, generation=generation,
                              shutdown_operation_id=operation_id)
                    sent = True
                except OSError:
                    # An unavailable local mailbox is not authority to close
                    # a live kill-on-close Job Object. Keep waiting/retrying.
                    pass
            if not deferred and time.monotonic() >= deadline:
                deferred = True
                try:
                    self.save("cooperative-stop-deferred", child_pid=self.child.pid, generation=generation,
                              shutdown_operation_id=operation_id)
                    self.event("cooperative_stop_deferred", child_pid=self.child.pid)
                except OSError:
                    pass
            time.sleep(0.1)

    def resume(self):
        if not self.acquire():
            raise RuntimeError("stop the current guard before explicit resume")
        try:
            self.marker.unlink(missing_ok=True)
            self.save("explicit-resume-pending-task-start", child_pid=None, consecutive_failures=0, next_retry_at=0.0)
            self.event("operator_resume_requested")
        finally:
            self.release()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--action", choices=["run", "status", "validate", "stop", "resume"], default="run")
    args = parser.parse_args(argv)
    try:
        guard = CoordinatorGuard(args.config)
        if args.action == "status":
            print(json.dumps(guard.read_state()))
        elif args.action == "validate":
            guard.launch_contract()
            print(json.dumps({"valid": True, "activated": False}))
        else:
            if os.name != "nt":
                raise RuntimeError("Windows service context required")
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError("elevated service control required")
            if args.action == "run":
                identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, timeout=10, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if '"S-1-5-18"' not in identity.stdout:
                    raise PermissionError("coordinator guard must run as SYSTEM")
                return guard.run()
            getattr(guard, args.action)()
        return 0
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "activated": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
