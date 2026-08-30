"""Module 124 — Docker/Container Escape Surface Check
Checks for privileged containers or an exposed docker.sock. A finding
means a contained process could break out to the host."""
import subprocess, json, datetime, os

def now_iso(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def check_docker_installed():
    try:
        out = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=10)
        return out.returncode == 0, out.stdout.strip()
    except FileNotFoundError:
        return False, None
    except Exception as e:
        return False, f"error: {type(e).__name__}: {e}"

def check_docker_sock():
    sock_path = "/var/run/docker.sock"
    exists = os.path.exists(sock_path)
    world_accessible = None
    if exists:
        try:
            import stat as statmod
            mode = os.stat(sock_path).st_mode
            world_accessible = bool(mode & statmod.S_IROTH or mode & statmod.S_IWOTH)
        except Exception:
            pass
    return exists, world_accessible

def list_privileged_containers():
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode != 0:
            return None
        names = out.stdout.strip().splitlines()
        privileged = []
        for name in names:
            inspect = subprocess.run(
                ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", name],
                capture_output=True, text=True, timeout=10
            )
            if inspect.stdout.strip() == "true":
                privileged.append(name)
        return privileged
    except Exception:
        return None

if __name__ == "__main__":
    print("--- Docker/Container Escape Surface Check ---\n")
    installed, version_info = check_docker_installed()
    print(f"Docker installed: {installed}  ({version_info})")

    sock_exists, sock_world_accessible = check_docker_sock()
    print(f"docker.sock exists: {sock_exists}, world-accessible: {sock_world_accessible}")

    privileged = list_privileged_containers() if installed else None
    print(f"Privileged containers running: {privileged}")

    finding_summary = (
        f"Docker installed: {installed}. "
        + (f"docker.sock world-accessible: {sock_world_accessible} — if True, ANY user "
           f"with access to that socket has root-equivalent control over the host. "
           if sock_exists else "docker.sock not present. ")
        + (f"Privileged containers currently running: {len(privileged)}. Each one has full "
           f"host device access — a real container-escape surface. "
           if privileged else
           "No privileged containers detected. " if installed else
           "Docker not installed — this check is not applicable on this system.")
    )
    print(f"\nFINDING: {finding_summary}")

    result = {"docker_installed": installed, "docker_sock_exists": sock_exists,
               "docker_sock_world_accessible": sock_world_accessible,
               "privileged_containers": privileged, "finding_summary": finding_summary,
               "timestamp": now_iso()}
    OUTPUT_DIR = "/data/data/com.termux/files/home/Watchdog/todo"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "module124_docker_escape_result.json"), "w") as f:
        json.dump(result, f, indent=2)
    print("Saved.")
