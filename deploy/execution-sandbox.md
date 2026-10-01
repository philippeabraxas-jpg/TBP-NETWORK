# deploy/execution-sandbox.md — confining what the harness executes (issue #180)

_Version française : [execution-sandbox.fr.md](execution-sandbox.fr.md)._

**TBP never executes anything.** The broker, OPA and the PEP *decide*: they answer
allow or deny. They never open a file, start a process or sandbox anything (§4.5,
"the executed action is the translated action"). That is deliberate and stays so.

Confining the *actual execution* of an allowed action is therefore **entirely the
integrator's job** — whoever plugs their own harness (agent framework, tool runner)
on TBP ("Before Tool Execution" in `tbp4.2.1/reference-stub/reference_stub_README.md`:
TBP answers, the calling application executes). This page is a reference for whoever
writes that harness. It is documentation only: no TBP code changes.

> A TBP "allow" says *this action is permitted by policy*. It does not say *this
> function is safe*. If the executor trusts the path it receives, a permitted
> `write_file("notes/a.txt")` and a symlink pointing out of the workspace are the same
> call as far as TBP can see.

## Four rules

1. **Resolve before you check, and do not check-then-use.** `os.path.abspath` does not
   resolve symlinks. `os.path.realpath` does, and `os.path.commonpath([root, final])`
   against the confined root closes `..` and encoding traversal that a naive prefix
   comparison lets through. But `realpath` + `commonpath` + `open` still leaves a window
   between the check and the open (TOCTOU): if something can swap a directory for a
   symlink in between, the check passed on a path that no longer is the one opened.
   Prefer a **single, race-free open beneath the root** — below — and keep
   `realpath`/`commonpath` as the portable first filter, not the only one.
2. **The executor is a separate process** from the decision point, with its own
   unprivileged account, a filesystem view limited to the workspace (mount namespace,
   container, or at least a dedicated user and directory), no credentials of the
   decision plane, and no route to the admin plane. Same separation of duties TBP
   imposes between deciding and executing, applied on the integrator's side.
3. **An explicit allow-list of actions**, never a generic "run this command" or "call
   this function by name" executor. Each action has typed parameters validated by the
   executor itself (length, charset, enumerations), not only by policy.
4. **Execute exactly what was authorised.** Bind the execution to the decision: the
   executor runs the action *and parameters* TBP evaluated (compare a digest of the
   canonical request with the decision's), not a re-read of the agent's output.

## Open beneath a root (Python)

`openat2` with `RESOLVE_BENEATH` is the kernel's own answer (Linux ≥ 5.6) and is the
better tool where the language exposes it. The portable equivalent below walks the path
one component at a time with `dir_fd` and `O_NOFOLLOW`: a symlink on the way is refused,
and there is no gap between checking and using, because there is no separate check.

```python
import os, stat

class SandboxViolation(PermissionError):
    pass

def open_beneath(root_fd: int, user_path: str, flags: int, mode: int = 0o600) -> int:
    """Open user_path relative to root_fd, never leaving it.

    Walks the path one component at a time with dir_fd and O_NOFOLLOW: a symlink
    anywhere on the way is refused, so there is no window between "check" and
    "use" for a swap (unlike realpath + commonpath + open).
    """
    parts = [p for p in user_path.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or "\0" in user_path:
        raise SandboxViolation(f"chemin refusé : {user_path!r}")
    dir_fd = os.dup(root_fd)
    try:
        for name in parts[:-1]:
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
        fd = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    except OSError as e:
        raise SandboxViolation(f"accès refusé : {user_path!r} ({e.strerror})") from e
    finally:
        os.close(dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise SandboxViolation(f"pas un fichier ordinaire : {user_path!r}")
    return fd

def write_file(root_fd: int, path: str, content: bytes) -> dict:
    fd = open_beneath(root_fd, path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return {"status": "written", "path": path}
```

The same call, written the naive way, is what `tbp4.2.1/tbp-v4-hard-shield/integrations/README.md`
used to show (`open(path, 'w')` on the received path). That file lives in the core repository
(`Responsible-Alliance-Protocol`, the `tbp4.2.1` submodule), where the example is annotated "illustration only, do not copy".

## What to test

A confinement that was never attacked is a guess. Keep these as tests of your harness:

| Input | Expected |
|---|---|
| `../x`, `sub/../../x` | refused |
| a symlink inside the workspace pointing outside | refused |
| a directory component replaced by a symlink between two calls | refused |
| a path with a NUL byte | refused |
| a directory, FIFO or device as final component | refused |
| `sub/a.txt` | written inside the workspace only |

## Precedent

The `invarian_debian` repository (`debian_broker/shadow_executor.py`) isolates the
executor from the decision broker (`ShadowExecutor` ≠ `broker.py`), keeps an explicit
allow-list of plugins, and confines paths with `realpath` + `commonpath`. It is a good
shape to start from; add the race-free open above to close the check-then-use window.

## What this does not cover

Network egress, CPU/memory limits, and what the *allowed* tool does once it runs
(a shell, a browser, a database client) are the executor's isolation to design.
Network isolation of the TBP cell itself is a separate subject (#186).
