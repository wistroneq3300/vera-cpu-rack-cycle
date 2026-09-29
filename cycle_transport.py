"""Bounded SSH and outband operations. Passwords never enter argv or evidence."""
from __future__ import annotations

import os
import shlex
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

USERS = {"bmc": "root", "os": "root", "lily_bmc": "service", "lily_os": "ubuntu"}

@dataclass
class Command:
    code: int
    output: str
    state: str = "RETURNED"
    duration: float = 0.0

    def data(self):
        return asdict(self)

class IdentityUnsafe(RuntimeError):
    pass

class Transport:
    def __init__(self, credentials, known_hosts):
        # Treat an omitted password and an explicit None identically. SSH key
        # authentication/passwordless sudo must not fail during string encoding.
        self.credentials = {role: "" if password is None else password
                            for role, password in credentials.items()}
        self.known_hosts = Path(known_hosts)

    def _connect(self, target, role, timeout):
        # Report rebuilding and CLI help do not require Paramiko to be installed.
        # Paramiko 2.x still references the moved TripleDES symbol at import
        # time; newer cryptography releases raise CryptographyDeprecationWarning
        # (a UserWarning subclass) on every SSH call. Silence that one message.
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message=r'.*TripleDES.*', category=UserWarning)
            import paramiko
        client = paramiko.SSHClient()
        # Campaign-isolated TOFU; later key changes fail. Hostname is separately
        # checked against operator-supplied inventory before any remote mutation.
        hostfile = self.known_hosts / (target.key + "_" + role)
        hostfile.parent.mkdir(parents=True, exist_ok=True)
        hostfile.touch(exist_ok=True)
        client.load_host_keys(str(hostfile))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        watchdog = threading.Timer(timeout, client.close)
        watchdog.daemon = True
        watchdog.start()
        try:
            client.connect(getattr(target, role + "_ip"),
                           username=os.environ.get(role.upper() + "_USER", USERS[role]),
                           password=self.credentials.get(role), timeout=timeout,
                           banner_timeout=timeout, auth_timeout=timeout,
                           look_for_keys=not bool(self.credentials.get(role)), allow_agent=True)
        except (paramiko.AuthenticationException, paramiko.BadHostKeyException) as exc:
            client.close()
            raise IdentityUnsafe(f"{role}: authentication or SSH host key validation failed") from exc
        except BaseException:
            # Clean up even on cancellation, then preserve the original exception.
            client.close()
            raise
        finally:
            watchdog.cancel()
        return client

    def ssh(self, target, role, command, timeout=60, sudo=False):
        start = time.monotonic()
        client = None
        watchdog = None
        sent = False
        chunks = []
        try:
            client = self._connect(target, role, min(10, timeout / 4))
            # Paramiko's exec/subsystem acknowledgement wait has no timeout of
            # its own. Closing the transport at the whole-command deadline
            # releases that wait as well as stalled reads/writes.
            watchdog = threading.Timer(max(.001, timeout - (time.monotonic() - start)), client.close)
            watchdog.daemon = True
            watchdog.start()
            channel = client.get_transport().open_session(timeout=min(10, timeout / 4))
            channel.set_combine_stderr(True)
            channel.settimeout(max(1, timeout - (time.monotonic() - start)))
            sudo = sudo and os.environ.get(role.upper() + "_USER", USERS[role]) != "root"
            if sudo:
                command = "sudo -S -p '' -- sh -c " + shlex.quote(command)
            # Once dispatch starts, a lost reply is ambiguous, never safe to retry.
            sent = True
            channel.exec_command("export LC_ALL=C; export PATH=/usr/sbin:/sbin:/usr/bin:/bin:$PATH; " + command)
            if sudo:
                channel.sendall((self.credentials.get(role, "") + "\n").encode())
            channel.shutdown_write()
            while True:
                while channel.recv_ready():
                    chunks.append(channel.recv(65536))
                    if time.monotonic() - start >= timeout:
                        raise TimeoutError("Command deadline exceeded")
                if channel.exit_status_ready() and not channel.recv_ready():
                    code = channel.recv_exit_status()
                    return Command(code, b"".join(chunks).decode(errors="replace"), "RETURNED" if code >= 0 else "RESPONSE_LOST", time.monotonic() - start)
                if time.monotonic() - start >= timeout:
                    raise TimeoutError("Command deadline exceeded")
                time.sleep(0.05)
        except IdentityUnsafe:
            raise
        except Exception as exc:
            output = b"".join(chunks).decode(errors="replace")
            output += f"\n{type(exc).__name__}: {exc}"
            # Redact any credential echoed by an exception or command wrapper.
            for secret in self.credentials.values():
                if secret:
                    output = output.replace(secret, "[REDACTED]")
            return Command(124 if isinstance(exc, (TimeoutError, socket.timeout)) else 255, output,
                           "RESPONSE_LOST" if sent else "NOT_ISSUED", time.monotonic() - start)
        finally:
            if watchdog:
                watchdog.cancel()
            if client:
                client.close()

    def upload(self, target, data, remote):
        client = self._connect(target, "os", 10)
        watchdog = threading.Timer(60, client.close)
        watchdog.daemon = True
        watchdog.start()
        try:
            with client.open_sftp() as sftp:
                sftp.get_channel().settimeout(60)
                # Exclusive create prevents accidental reuse or replacement.
                with sftp.file(remote, "wx") as stream:
                    stream.write(data)
                sftp.chmod(remote, 0o700)
        finally:
            watchdog.cancel()
            client.close()

    def oob(self, target, command, timeout=30):
        env = os.environ.copy()
        env["IPMI_PASSWORD"] = self.credentials.get("bmc", "")
        argv = ["ipmitool", "-I", "lanplus", "-C", "17", "-H", target.bmc_ip,
                "-U", os.environ.get("BMC_USER", "root"), "-E", *shlex.split(command)]
        start = time.monotonic()
        try:
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, check=False)
            return Command(result.returncode, result.stdout + result.stderr, duration=time.monotonic() - start)
        except subprocess.TimeoutExpired as exc:
            data = (exc.stdout or b"") + (exc.stderr or b"")
            return Command(124, data.decode(errors="replace") if isinstance(data, bytes) else data, "RESPONSE_LOST", time.monotonic() - start)
        except OSError as exc:
            return Command(127, str(exc), "NOT_ISSUED", time.monotonic() - start)

    def local_dependencies(self):
        if shutil.which("ipmitool"):
            return Command(0, "ipmitool is installed")
        if not shutil.which("apt-get"):
            return Command(127, "ipmitool missing; apt-get unavailable on orchestrator")
        prefix = [] if hasattr(os, "geteuid") and os.geteuid() == 0 else ["sudo", "-n"]
        output = []
        for args in (["apt-get", "update"], ["apt-get", "install", "-y", "ipmitool"]):
            try:
                result = subprocess.run(prefix + args, capture_output=True, text=True, timeout=600,
                                        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"}, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return Command(127, str(exc))
            output.append(result.stdout + result.stderr)
            if result.returncode:
                return Command(result.returncode, "\n".join(output))
        return Command(0, "\n".join(output))
