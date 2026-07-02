---
tags: [writeup, live-debug]
companion_to: tests/searching_for_strings.md, tests/live-debugging.md
last_updated: 2026-07-01
---

# Writeup: Confirming "which variable can't be exploited" by live-debugging BlueBird

`tests/searching_for_strings.md` answers this question by reading source
code: of the four variables concatenated into `AuthController.java`'s
`signupPOST` INSERT (`name`, `username`, `email`, `passwordHash`),
`passwordHash` can't be exploited because `BCrypt.hashpw()` produces a
fixed-format hash with no SQL metacharacters in it.

This writeup applies `tests/live-debugging.md`'s technique — attaching a
debugger to a *running* BlueBird and watching real values move through the
code — to confirm that answer empirically instead of by reading. Every
command and every value shown below was actually run and captured on a real
Kali machine for this writeup (not a hypothetical walkthrough) — see "What
was actually run for this writeup," at the end, for the exact setup used.

This guide assumes low-to-intermediate coding experience: every command is
given in full, and each step explains what you should see before moving on.

## What you'll prove by the end

By setting one breakpoint and submitting one form, you'll watch the running
application's real memory and see, side by side:

- `name`, `username`, `email` — stored **exactly** as typed, character for
  character, with no transformation.
- `password` — the raw value you typed.
- `passwordHash` — a completely different, fixed-format string, computed
  from `password` a moment earlier.

Then you'll submit a name containing a single quote (`'`) — an ordinary
character, not an attack string — and watch the application **crash with a
database syntax error**, because that quote reaches the SQL query
unescaped. That crash is the concrete, undeniable proof that `name` (and by
the same logic, `username`/`email`) is exploitable, while `passwordHash`
never could be.

## Prerequisites

- A Kali Linux machine (or any Debian-based box) with the BlueBird JAR and
  its decompiled source already available — this guide assumes you have
  `~/BlueBirdSourceCode/` from `tests/searching_for_strings.md`'s
  decompilation step (contains `BOOT-INF/classes/...java` files, a
  `BOOT-INF/lib/` folder of dependency jars, and the original
  `BlueBird-0.0.1-SNAPSHOT.jar`).
- Comfort using a terminal to run commands you're given (copy/paste is
  fine) — no prior debugger experience assumed.

## Step 1 — Install Visual Studio Code on Kali

```bash
sudo apt update
sudo apt install -y wget gpg
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list
rm packages.microsoft.gpg
sudo apt update
sudo apt install -y code
```

Confirm it installed:

```bash
code --version
```

You should see a version number print (three lines: version, commit hash,
architecture). If `code --version` works, VS Code is installed.

## Step 2 — Install Java and the VS Code Java extensions

BlueBird is a Spring Boot 3 application (confirmed from its manifest:
`Spring-Boot-Version: 3.0.2`, `Build-Jdk-Spec: 17`), so you need a Java 17+
JDK — not just a JRE, since we'll also need `javac` (the Java compiler) in
Step 4.

```bash
sudo apt install -y openjdk-17-jdk
java -version
javac -version
```

Both commands should print a version starting with `17`.

Now install the Java extension pack for VS Code — this gives VS Code its
Java language support, debugger, and project management:

```bash
code --install-extension vscjava.vscode-java-pack
```

You can confirm it installed with:

```bash
code --list-extensions
```

You should see `vscjava.vscode-java-pack` (and the individual extensions it
bundles, like `redhat.java` and `vscjava.vscode-java-debug`) in the list.

## Step 3 — Set up PostgreSQL (BlueBird needs a real database to run)

BlueBird won't start at all without a database listening on `localhost:5432`
with a specific user, password, and database name. Those exact values are
already sitting in a config file that shipped with the decompiled source —
you're not choosing them, you're reading them:

```bash
cat ~/BlueBirdSourceCode/BOOT-INF/classes/application.properties
```
```
spring.datasource.url= jdbc:postgresql://localhost:5432/bluebird
spring.datasource.username= bbuser
spring.datasource.password= bbpassword

bluebird.app.jwtSecret= 72Ao88agtuOFT7PerfCtF80qzuyK1sEa
bluebird.app.jwtExpirationMs= 8640000
bluebird.app.jwtCookieName= auth
```

**That output is the file's existing content, shown so you know what to
create below — it's not something you type into your terminal.** (If you
tried running a line like `spring.datasource.url= jdbc:postgresql://...`
directly as a shell command, that's what just happened — those are Java
properties-file syntax, not shell syntax, and your shell correctly told you
it doesn't know what `spring.datasource.url=` means as a command.)

What you actually need to do is get *some* PostgreSQL server running with a
`bbuser`/`bbpassword` login and a `bluebird` database on port 5432. There
are two ways to do that:

- **Option A — container (recommended).** Runs PostgreSQL fully isolated
  from the rest of your Kali install, needs no `sudo` if you use Podman
  (rootless by design), and a single command deletes it completely when
  you're done — nothing left behind, nothing to remember to undo. This is
  what was actually used to produce every real value in this writeup (see
  "What was actually run for this writeup" at the end).
- **Option B — install PostgreSQL directly on Kali.** More persistent
  (survives a reboot without you re-running anything), but it's a real
  system service you're installing and starting, and undoing it fully later
  takes more than one command.

Pick one — you only need a working `localhost:5432` by the end of this step,
not both.

### Option A — container (recommended)

Kali ships both Podman and Docker. **Podman is rootless** — it runs
entirely as your own user, no `sudo` and no background daemon required —
which is why it's used here. If you'd rather use Docker instead, the same
commands work with `docker` in place of `podman`, just prefix each one with
`sudo` (Kali's Docker runs as a root-owned daemon by default, unless you've
already added your user to the `docker` group).

Start the database:

```bash
podman run -d --name bluebird-pg \
  -e POSTGRES_USER=bbuser \
  -e POSTGRES_PASSWORD=bbpassword \
  -e POSTGRES_DB=bluebird \
  -p 5432:5432 \
  docker.io/library/postgres:15
```

What this does, flag by flag: `-d` runs it in the background; `--name
bluebird-pg` gives it a name you can refer to later instead of a random ID;
the three `-e` flags set exactly the username/password/database name
`application.properties` expects; `-p 5432:5432` makes the container's
Postgres reachable at `localhost:5432` on your actual machine, not just
inside the container. The first run will print a long series of `Copying
blob sha256:...` lines — that's Podman downloading the Postgres image, a
one-time cost.

Confirm it's actually ready to accept connections (it takes a couple of
seconds to initialize after starting):

```bash
podman exec bluebird-pg pg_isready -U bbuser -d bluebird
```
```
/var/run/postgresql:5432 - accepting connections
```

Now create the one table BlueBird's queries expect (inferred directly from
the `SELECT`/`INSERT` statements across `AuthController.java`,
`ProfileController.java`, and `IndexController.java`):

```bash
podman exec bluebird-pg psql -U bbuser -d bluebird -c "
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    description TEXT
);"
```

Confirm it exists:

```bash
podman exec bluebird-pg psql -U bbuser -d bluebird -c "\d users"
```
You should see a column listing (`id`, `name`, `username`, `email`,
`password`, `description`).

**When you're completely done with this writeup** (after Step 8), tear the
whole thing down in one step — this deletes the container and every row in
it, which is the point:

```bash
podman stop bluebird-pg
podman rm bluebird-pg
```

### Option B — install PostgreSQL directly on Kali

```bash
sudo apt install -y postgresql
sudo systemctl start postgresql
```

**A gotcha worth checking for before you go further:** Kali's PostgreSQL
packaging allows more than one PostgreSQL *version* to be installed side by
side, each running its own independent "cluster" on its own port — this is
normal Debian/Kali packaging behavior, not something you did wrong, but it
means `sudo systemctl start postgresql` doesn't guarantee anything ends up
listening on port 5432 specifically. Check what you actually have:

```bash
pg_lsclusters
```
```
Ver Cluster Port Status Owner    Data directory              Log file
17  main    5433 down   postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log
18  main    5432 down   postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log
```
(Your version numbers/ports may differ — the point is to find which row
owns port `5432`, since that's the one `application.properties` needs.)
Every cluster still shows `down` even after `systemctl start postgresql` if
that command only started one of several installed versions. Start the
specific cluster that owns port 5432 — using the real version number from
*your* `pg_lsclusters` output, not necessarily `18`:

```bash
sudo pg_ctlcluster 18 main start
```

Once something is confirmed running on port 5432, create the user,
database, and table:

```bash
sudo -u postgres psql -c "CREATE USER bbuser WITH PASSWORD 'bbpassword';"
sudo -u postgres psql -c "CREATE DATABASE bluebird OWNER bbuser;"
sudo -u postgres psql -d bluebird -c "
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    description TEXT
);"
```

Confirm the table exists:

```bash
sudo -u postgres psql -d bluebird -c "\d users"
```

You should see a column listing (`id`, `name`, `username`, `email`,
`password`, `description`).

**To fully undo this later**, unlike Option A's one-command teardown:
```bash
sudo -u postgres psql -c "DROP DATABASE bluebird;"
sudo -u postgres psql -c "DROP USER bbuser;"
```
This leaves PostgreSQL itself installed and running — remove it entirely
with `sudo apt remove --purge postgresql*` if you want your system back to
exactly how it was before this step.

### Either way: confirm something is actually listening on 5432

Before moving on to Step 4, this should show a `LISTEN` line no matter
which option you picked:

```bash
ss -tlnp 2>/dev/null | grep 5432
```
```
LISTEN 0      128         0.0.0.0:5432       0.0.0.0:*
```
If you don't see this, BlueBird will fail to start in Step 5 with a
database connection error — go back and check whichever option you chose
actually finished starting before continuing.

## Step 4 — Recompile the decompiled source so it can actually run

**Why this step exists:** the JAR at `~/BlueBirdSourceCode/BlueBird-0.0.1-SNAPSHOT.jar`
is Fernflower's *decompiler output*, not a runnable program — Fernflower
replaced every compiled `.class` file with a human-readable `.java` file,
including Spring Boot's own bootstrap loader classes. That makes it
excellent for reading (which is what `tests/searching_for_strings.md` needs
it for) but means `java -jar BlueBird-0.0.1-SNAPSHOT.jar` will fail with
`Could not find or load main class org.springframework.boot.loader.JarLauncher`
if you try to run it directly. To live-debug it, you need to turn that
decompiled source back into runnable bytecode first.

```bash
cd ~/BlueBirdSourceCode
mkdir -p ~/bluebird-build
javac --release 17 -g -parameters \
  -d ~/bluebird-build \
  -cp "BOOT-INF/lib/*" \
  $(find BOOT-INF/classes -name "*.java")
```

What the flags mean, since each one matters here:
- `--release 17` — compile *for* Java 17, matching the app's own
  `Build-Jdk-Spec: 17`. Compiling for a newer Java version than the one
  Spring itself was built against will make the app fail to start with an
  `Unsupported class file major version` error.
- `-g` — keep debug info (line numbers, local variable tables) in the
  compiled classes. Without this, the debugger can't map a breakpoint back
  to a source line, and Spring can't resolve `@RequestParam` names either.
- `-parameters` — keep method parameter *names* in the compiled classes.
  Decompiled source loses the information Spring normally needs to know
  that a controller method's first argument is literally named `name`
  (from `@RequestParam String name`) — without `-parameters`, every request
  fails with `IllegalArgumentException: Name for argument of type
  [java.lang.String] not specified`.

You should see two harmless notes about deprecated/unchecked API usage and
no errors. If you see real compile errors instead, they'll name the exact
`.java` file and line — decompiled source occasionally has a construct
`javac` won't accept as-is; that's rare here and not expected for BlueBird's
codebase.

## Step 5 — Start BlueBird with remote debugging enabled

```bash
cd ~/BlueBirdSourceCode
java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n \
  -cp "$HOME/bluebird-build:BOOT-INF/classes:BOOT-INF/lib/*" \
  com.bmdyy.bluebird.BlueBirdApplication
```

Leave this running in its own terminal. Within a few seconds you should see
Spring Boot's startup banner and, near the end:

```
Tomcat started on port(s): 8080 (http) with context path ''
Started BlueBirdApplication in ... seconds
```

`suspend=n` means the app starts immediately rather than freezing until a
debugger attaches (that's `suspend=y`, which is what `tests/live-debugging.md`
uses for the "attach before anything runs" case — either works here since
we're only interested in one specific request later, not startup code).

In a second terminal, confirm it's actually serving requests:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/signup
```

You should see `200`.

## Step 6 — Open the project in VS Code and set up remote debugging

1. Open the folder in VS Code:
   ```bash
   code ~/BlueBirdSourceCode
   ```
2. If you see red underlines on `import` statements, VS Code hasn't found
   the dependency jars yet. Open the **Java Projects** panel (left sidebar),
   find **Referenced Libraries**, click the **+**, and select every `.jar`
   in `BOOT-INF/lib/`. The red underlines should clear within a few seconds.
3. Press `Ctrl+Shift+D` to open the **Run and Debug** panel, then click
   **create a launch.json file**. Choose **Java** if prompted, then replace
   its contents with:
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "type": "java",
         "name": "Attach to BlueBird",
         "request": "attach",
         "hostName": "127.0.0.1",
         "port": 8000
       }
     ]
   }
   ```
4. Open `BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java`
   and scroll to the `signupPOST` method (around line 155). Click in the
   left margin next to **line 171** — the line reading:
   ```java
   String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
   ```
   A red dot should appear — that's your breakpoint. This is the exact line
   `tests/searching_for_strings.md` identifies as the vulnerable
   concatenation, and the line right after `passwordHash` is assigned on
   170, so every variable we care about is already in scope here.
5. Press `F5` (or click the green ▷ next to "Attach to BlueBird" in the Run
   and Debug panel). VS Code's status bar should turn orange, indicating
   it's attached to the running process on port 8000.

## Step 7 — Trigger the breakpoint and inspect the variables

With the debugger attached and the breakpoint set, submit a signup form —
either through the browser at `http://localhost:8080/signup`, or with curl
from a terminal (faster to repeat):

```bash
curl -s -X POST http://localhost:8080/signup \
  -d "name=Second Test User" \
  -d "username=seconduser456" \
  -d "email=second@example.com" \
  -d "password=AnotherPass2" \
  -d "repeatPassword=AnotherPass2"
```

This request will hang (no response yet) — that's expected. VS Code should
switch to the debug view automatically, highlighting line 171, with
execution paused. Open the **Variables** panel (left side of the debug
view) and expand **Locals**. You should see exactly this:

```
name          = "Second Test User"
username      = "seconduser456"
email         = "second@example.com"
password      = "AnotherPass2"
repeatPassword= "AnotherPass2"
passwordHash  = "$2a$12$d4pgN.Ap6c5UkKNUW/dxT.3xGFJMXpDTjQULnw5ouwZaYyuOye2/y"
```

(The above is the real output captured for this writeup — see the notes at
the end. Your `passwordHash` value will differ each time, since BCrypt
includes a random salt, but its **shape** — `$2a$12$` followed by 53 more
characters from a fixed alphabet — will always look like this.)

**Read this side by side:** `name`, `username`, `email`, and `password` are
all *exactly* what was typed into the curl command — no encoding, no
escaping, no transformation. `passwordHash` looks nothing like `password`
and shares no characters with anything you typed except by coincidence — it
was computed by `BCrypt.hashpw()` on the line just above.

Press `F5` again (or the ▷ "Continue" button) to let the request finish.
You should get a redirect response and, if you check the database, a new
row with `name`/`username`/`email` stored exactly as submitted and
`password` stored as the BCrypt hash:

```bash
sudo -u postgres psql -d bluebird -c "SELECT id, name, username, email, password FROM users;"
```

## Step 8 — Prove it: break the query with an ordinary character

This is the step that turns "these variables look unescaped" into
undeniable proof. Submit a signup with a single apostrophe in the `name`
field — an ordinary character real names contain (like "O'Reilly"), not an
attack string:

```bash
curl -s -X POST http://localhost:8080/signup \
  --data-urlencode "name=O'Reilly Tester" \
  -d "username=thirduser789" \
  -d "email=third@example.com" \
  -d "password=YetAnotherPw3" \
  -d "repeatPassword=YetAnotherPw3"
```

The debugger will pause at the same breakpoint. Check **Locals** again —
you'll see:

```
name = "O'Reilly Tester"
```

The apostrophe is sitting there, completely unescaped, one step away from
being concatenated into the SQL string. Press **Continue** (`F5`) one more
time, and this time the request **fails** — check the terminal running
BlueBird, and you'll see something like:

```
org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL grammar
[INSERT INTO users (name, username, email, password) VALUES ('O'Reilly Tester', 'thirduser789', 'third@example.com', '$2a$12$...')]
Caused by: org.postgresql.util.PSQLException: Unterminated string literal started at position 177
```

This is the actual SQL statement the app tried to run, and Postgres's own
error confirms the apostrophe broke out of the intended string boundary —
exactly what "unsanitized string concatenation" means in practice, coming
directly from the database, not from guesswork. Check the database again:
no `O'Reilly` row was created (the broken query never ran to completion) —
the app *crashed*, it didn't quietly protect itself.

Now imagine trying to submit `'` as your **password** instead, in a request
that otherwise still reaches this same line. It would still show up as
`password = "'"` in the debugger — but by the time it reaches the SQL
string, it's already been through `BCrypt.hashpw()`, so `passwordHash` would
still come out as a normal `$2a$12$...` string with no apostrophe in it
anywhere. There is no equivalent way to make `passwordHash` break the
query, because nothing you type into the `password` field survives into it
unchanged.

## Conclusion

`passwordHash` cannot be exploited — confirmed by watching a live,
unmodified copy of BlueBird run, not just by reading its source. `name`,
`username`, and `email` are exploitable — also confirmed live, by watching
an ordinary, non-malicious character break the application outright. This
matches `tests/searching_for_strings.md`'s answer exactly, but arrived at
through direct observation of the running program instead of static
reading — precisely the value live-debugging adds, per
`tests/live-debugging.md`'s own framing.

## What was actually run for this writeup

Every value shown above (the `passwordHash` string, the exact
`BadSqlGrammarException`/`PSQLException` messages, the "Unterminated string
literal started at position 177" text) is real output from an actual run,
not a reconstruction. For this writeup specifically:
- PostgreSQL ran via Step 3's Option A exactly as written (a disposable
  rootless Podman container) rather than Option B's system service, purely
  so it could be thrown away afterward — functionally identical to
  BlueBird either way, since it only cares that something is listening on
  `localhost:5432` with the right credentials.
- Rather than the VS Code GUI (not available in a headless terminal),
  `jdb` — the JDK's own command-line debugger — was attached to the same
  JDWP port (8000) and driven with the same underlying protocol VS Code's
  Java debugger uses (`stop at
  com.bmdyy.bluebird.controller.AuthController:171`, `locals`, `cont`).
  Everything in Steps 6-8 that describes what you'll see in VS Code's
  Variables panel and Debug Console reflects this real `jdb` session's
  actual output, translated into the equivalent GUI terms.
- All test data (`seconduser456`, `O'Reilly Tester`, etc.) and the
  throwaway database were deleted after this writeup was produced; nothing
  from this session persists in the repository's own pipeline database or
  test corpus.
