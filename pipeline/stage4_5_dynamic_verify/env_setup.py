"""Stage 4.5 environment automation.

Automates the manual process validated in
tests/searching_for_strings_live_debug_writeup.md: recompile the decompiled
source (the shipped jar is Fernflower's decompiler *output*, not a runnable
program -- java -jar on it fails with ClassNotFoundException on Spring
Boot's own bootstrap loader), stand up a disposable local Postgres via
Podman, apply a human-authored schema, run the app directly via classpath.

Per CLAUDE.md: this automates *re-running* against a target already worked
out this way once. It does not infer a DB schema or a request shape for an
arbitrary new target -- both are human-supplied preconditions (a schema
file, request-templates.json), never derived from decompiled source.
"""

import os
import signal
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.exceptions import RequestException

from pipeline.stage4_5_dynamic_verify import guard


@dataclass
class BuildResult:
    build_dir: str
    start_class: str
    compiled_ok: bool
    stderr_tail: str


def read_start_class(jar_path: str) -> str:
    """Read Start-Class out of META-INF/MANIFEST.MF inside jar_path."""
    with zipfile.ZipFile(jar_path) as zf:
        manifest_text = zf.read("META-INF/MANIFEST.MF").decode("utf-8")
    # Unwrap MANIFEST.MF's 72-byte-line continuation format (a continuation
    # line starts with a single space) before scanning for Start-Class.
    unwrapped = manifest_text.replace("\r\n", "\n").replace("\n ", "")
    for line in unwrapped.splitlines():
        if line.startswith("Start-Class:"):
            return line.split(":", 1)[1].strip()
    raise ValueError(f"no Start-Class entry found in {jar_path}'s META-INF/MANIFEST.MF")


def recompile_source(source_root: str, build_dir: str, release: str = "17", log=print, force: bool = False) -> BuildResult:
    """javac --release <release> -g -parameters -d build_dir
    -cp <source_root>/BOOT-INF/lib/* <every .java under source_root/BOOT-INF/classes>.

    -g keeps debug info (line numbers, local variable tables) the debugger
    and Stage 4.5's own probes need; -parameters keeps method parameter
    names, which Spring needs at runtime to resolve @RequestParam names by
    name (decompiled source loses both). --release must match the target's
    own Build-Jdk-Spec or the app fails at startup with
    "Unsupported class file major version" (Spring's ASM can't parse newer
    bytecode than it was built for).

    Idempotent: skipped if build_dir already contains the compiled
    Start-Class, unless force=True.
    """
    source_root = Path(source_root)
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)

    jar_candidates = list(source_root.glob("*.jar"))
    if not jar_candidates:
        raise FileNotFoundError(f"no .jar found directly under {source_root} to read Start-Class from")
    start_class = read_start_class(str(jar_candidates[0]))

    start_class_path = build_dir / (start_class.replace(".", "/") + ".class")
    if start_class_path.exists() and not force:
        log(f"skip recompile: {start_class_path} already exists")
        return BuildResult(build_dir=str(build_dir), start_class=start_class, compiled_ok=True, stderr_tail="")

    classes_root = source_root / "BOOT-INF" / "classes"
    java_files = [str(p) for p in classes_root.rglob("*.java")]
    if not java_files:
        raise FileNotFoundError(f"no .java files found under {classes_root}")

    cmd = [
        "javac", "--release", release, "-g", "-parameters",
        "-d", str(build_dir),
        "-cp", str(source_root / "BOOT-INF" / "lib" / "*"),
    ] + java_files

    result = subprocess.run(cmd, capture_output=True, text=True)
    log(result.stdout)
    if result.stderr:
        log(result.stderr)
    compiled_ok = result.returncode == 0 and start_class_path.exists()
    return BuildResult(
        build_dir=str(build_dir),
        start_class=start_class,
        compiled_ok=compiled_ok,
        stderr_tail=result.stderr[-2000:],
    )


def start_postgres_container(container_name, db_user, db_password, db_name,
                              port=5432, image="docker.io/library/postgres:15", log=print) -> dict:
    guard.validate_local_target("localhost")
    cmd = [
        "podman", "run", "-d", "--name", container_name,
        "-e", f"POSTGRES_USER={db_user}",
        "-e", f"POSTGRES_PASSWORD={db_password}",
        "-e", f"POSTGRES_DB={db_name}",
        "-p", f"{port}:5432",
        image,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"podman run failed: {result.stderr.strip()}")
    log(result.stdout.strip())
    return {"container_id": result.stdout.strip(), "container_name": container_name}


def wait_for_db_ready(container_name, db_user, db_name, timeout=30) -> None:
    deadline = time.monotonic() + timeout
    last_stderr = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["podman", "exec", container_name, "pg_isready", "-U", db_user, "-d", db_name],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return
        last_stderr = result.stderr.strip()
        time.sleep(1)
    raise TimeoutError(f"{container_name} did not become ready within {timeout}s (last: {last_stderr})")


def apply_schema(container_name, db_user, db_name, schema_sql_path: str) -> None:
    """Pipes a human-authored schema file into the container's psql. Never
    generates or infers a schema -- see CLAUDE.md's Stage 4.5 precondition."""
    schema_sql = Path(schema_sql_path).read_text()
    result = subprocess.run(
        ["podman", "exec", "-i", container_name, "psql", "-U", db_user, "-d", db_name],
        input=schema_sql, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"apply_schema failed: {result.stderr.strip()}")


def start_app(build_dir, source_root, start_class, app_port=8080,
              db_host="localhost", db_port=None, db_name=None, db_user=None, db_password=None,
              log_path=None, log=print) -> dict:
    """Launches the target directly via classpath (bypassing the decompiled
    jar's broken bootstrap loader entirely). server.port and the datasource
    connection are passed as Spring Boot property-override program
    arguments (--server.port=..., --spring.datasource.url=...) -- without
    these, the app falls back to whatever is hardcoded in its own
    application.properties (its default port, and *whichever* Postgres
    instance happens to be listening on the default port), which is exactly
    the kind of port conflict / silently-wrong-database connection this
    stage cannot tolerate, since Stage 4.5's whole guarantee is knowing
    precisely which disposable local replica a probe battery ran against."""
    guard.validate_local_target("localhost")
    source_root = Path(source_root)
    build_dir = Path(build_dir)
    if log_path is None:
        log_path = str(build_dir / ".." / "app.log")

    classpath = f"{build_dir}:{source_root / 'BOOT-INF' / 'classes'}:{source_root / 'BOOT-INF' / 'lib' / '*'}"
    cmd = ["java", "-cp", classpath, start_class, f"--server.port={app_port}"]
    if db_name:
        cmd.append(f"--spring.datasource.url=jdbc:postgresql://{db_host}:{db_port}/{db_name}")
    if db_user:
        cmd.append(f"--spring.datasource.username={db_user}")
    if db_password:
        cmd.append(f"--spring.datasource.password={db_password}")

    log_file = open(log_path, "w")
    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,  # detach from our process group so it outlives this call
    )
    log(f"started {start_class} as PID {proc.pid}, logging to {log_path}")
    return {"pid": proc.pid, "log_path": log_path}


def wait_for_app_ready(app_host, app_port, path="/", timeout=60) -> None:
    guard.validate_local_target(app_host)
    deadline = time.monotonic() + timeout
    url = f"http://{app_host}:{app_port}{path}"
    last_error = None
    while time.monotonic() < deadline:
        try:
            requests.get(url, timeout=3)
            return  # any response at all (even a non-2xx status) means the server is up
        except RequestException as e:
            last_error = e
            time.sleep(1)
    raise TimeoutError(f"{url} did not respond within {timeout}s (last error: {last_error})")


def register_environment(conn, source_root, build_dir, start_class, app_host, app_port,
                          app_pid, app_log_path, db_container_name, db_host, db_port,
                          db_user, db_name) -> int:
    cur = conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_host, "
        "app_port, app_pid, app_log_path, db_container_name, db_host, db_port, db_user, db_name, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running')",
        (source_root, build_dir, start_class, app_host, app_port, app_pid, app_log_path,
         db_container_name, db_host, db_port, db_user, db_name),
    )
    conn.commit()
    return cur.lastrowid


def teardown_environment(conn, env_id, log=print) -> None:
    row = conn.execute("SELECT * FROM target_environments WHERE env_id = ?", (env_id,)).fetchone()
    if row is None:
        raise ValueError(f"no target_environments row with env_id={env_id}")

    if row["db_container_name"]:
        for args in (["podman", "stop", row["db_container_name"]], ["podman", "rm", row["db_container_name"]]):
            result = subprocess.run(args, capture_output=True, text=True)
            if result.returncode != 0:
                log(f"{' '.join(args)}: {result.stderr.strip()}")
        log(f"stopped+removed container {row['db_container_name']}")

    if row["app_pid"]:
        try:
            os.kill(row["app_pid"], signal.SIGTERM)
            log(f"sent SIGTERM to app PID {row['app_pid']}")
        except ProcessLookupError:
            log(f"app PID {row['app_pid']} already gone")

    conn.execute(
        "UPDATE target_environments SET status = 'stopped', stopped_at = CURRENT_TIMESTAMP WHERE env_id = ?",
        (env_id,),
    )
    conn.commit()
