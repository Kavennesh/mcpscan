"""Fixture 6 of 7 -- containment introspection via /proc. Pins the namespace,
capability and user flags all at once.

The headline check is ``/proc/1/root``. In the default *private* PID namespace
this is harmless: PID 1 is the container's own init and ``/proc/1/root`` is the
container's own rootfs. Under ``--pid=host`` it is the host's init, and
``/proc/1/root/`` is the host filesystem, readable straight through with no
exploit involved -- open ``/proc/1/root/etc/shadow`` and you are done. So this
compares the device number of ``/proc/1/root/.`` against ``/``: equal means
contained, different means the PID namespace was shared.

The remaining checks assert the properties the run flags are supposed to
produce, rather than trusting that the flags were passed:

* ``uid != 0``                  -- ``--user 65532``
* ``CapEff``/``CapPrm``/``CapBnd`` all zero -- ``--cap-drop ALL``
* ``NoNewPrivs: 1``             -- ``--security-opt=no-new-privileges``
* ``Seccomp: 2`` (filter mode)  -- the daemon's builtin profile, not ``unconfined``
* ``/proc/kcore`` masked        -- rules out ``systempaths=unconfined``; an
                                   unmasked kcore is host RAM
* no ``docker.sock``            -- the single most direct container escape there is
* ``/sys/fs/cgroup`` not writable -- the ``release_agent`` escape needs it

Reading these from inside is the point. A flag can be present and inert; this
observes the result.
"""

from __future__ import annotations

import os

from _guard import emit, require_sandbox

FIXTURE = "procroot"

require_sandbox(FIXTURE)

DOCKER_SOCKETS = ["/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock"]


def _pid_namespace_contained() -> dict[str, object]:
    """Is /proc/1 our own init, or the host's?"""
    try:
        root_dev = os.stat("/").st_dev
        init_dev = os.stat("/proc/1/root/.").st_dev
    except PermissionError as exc:
        # PID 1 belongs to another user -- we cannot even look, which is itself
        # containment. Reported distinctly so it is never confused with a pass.
        return {"contained": True, "via": "permission-denied", "detail": str(exc)}
    except OSError as exc:
        return {"contained": True, "via": "unreadable", "detail": str(exc)}
    return {
        "contained": root_dev == init_dev,
        "via": "st_dev",
        "root_dev": root_dev,
        "init_dev": init_dev,
        "init_cmdline": _read("/proc/1/cmdline").replace("\0", " ").strip(),
    }


def _read(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError as exc:
        return f"<unreadable: {exc}>"


def _status_fields() -> dict[str, str]:
    wanted = {
        "Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
        "NoNewPrivs", "Seccomp",
    }
    found: dict[str, str] = {}
    for line in _read("/proc/self/status", limit=8192).splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            found[key] = value.strip()
    return found


def _host_shadow_readable() -> bool:
    """The payoff of a shared PID namespace, checked directly."""
    try:
        with open("/proc/1/root/etc/shadow", "rb") as handle:
            return bool(handle.read(1))
    except OSError:
        return False


def _kcore_masked() -> dict[str, object]:
    """Docker masks /proc/kcore. Unmasked, it is a window onto physical memory."""
    try:
        size = os.stat("/proc/kcore").st_size
    except OSError as exc:
        return {"masked": True, "via": "absent", "detail": str(exc)}
    try:
        with open("/proc/kcore", "rb") as handle:
            readable = bool(handle.read(1))
    except OSError as exc:
        return {"masked": True, "via": "unreadable", "detail": str(exc), "size": size}
    return {"masked": not readable, "via": "read", "size": size}


def _cgroup_writable() -> bool:
    for candidate in ("/sys/fs/cgroup", "/sys/fs/cgroup/cgroup.procs"):
        if os.access(candidate, os.W_OK):
            return True
    return False


status = _status_fields()
caps = {k: v for k, v in status.items() if k.startswith("Cap")}

emit(
    FIXTURE,
    [],
    uid=os.getuid(),
    gid=os.getgid(),
    is_root=os.getuid() == 0,
    pid_namespace=_pid_namespace_contained(),
    host_shadow_readable=_host_shadow_readable(),
    capabilities=caps,
    caps_all_zero=all(v == "0000000000000000" for v in caps.values()),
    no_new_privs=status.get("NoNewPrivs"),
    seccomp_mode=status.get("Seccomp"),
    kcore=_kcore_masked(),
    cgroup_writable=_cgroup_writable(),
    docker_sockets=[s for s in DOCKER_SOCKETS if os.path.exists(s)],
)

raise SystemExit(0)
