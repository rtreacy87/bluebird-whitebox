---
tags: [lab, attack/web]
module: advanced_sql_injections
last_updated: 2026-05-22
---

# Lab: Searching for Strings

Target access: SSH to the target with `student:academy.hackthebox.com` and SCP the JAR from `/opt/bluebird`. Requires the Fernflower decompilation setup from [[labs/htb/advanced_sql_injections/decompiling_java_archives]].

This lab is fully CLI-based using Fernflower and grep. VS Code is noted as a GUI browsing option but is not required.

## Tool Installation

See [[labs/htb/advanced_sql_injections/decompiling_java_archives]] for the full setup and troubleshooting.

**jadx (no Java setup required):**
```bash
sudo apt install jadx -y
jadx -d BlueBirdSourceCode/ bluebird/BlueBird-0.0.1-SNAPSHOT.jar
```

**Fernflower (verified working with `openjdk-17-jdk`):**
```bash
git clone https://github.com/fesh0r/fernflower.git
sudo apt install openjdk-17-jdk -y
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
cd fernflower/
./gradlew build -x test
cd ..
```

---

## Question 1 — Which variable in the INSERT query cannot be exploited?

**Goal:** Decompile the BlueBird JAR, find all INSERT statements in the source, and identify which variable in the INSERT concatenation cannot be exploited for SQL injection.

**Why look for INSERT statements specifically:** SQL injection in SELECT queries gets the most attention, but INSERT, UPDATE, and DELETE statements are equally worth auditing. An injectable INSERT can write arbitrary data to the database — and if stacked queries are supported, it can execute additional SQL beyond the INSERT itself. The question frames this as finding the *un*-exploitable variable, which teaches a critical skill: not every concatenated value is a usable injection point, even if it looks like one at first glance.

### Step 1 — Acquire and decompile the JAR

```bash
scp -r student@<TARGET_IP>:/opt/bluebird ./
mkdir BlueBirdSourceCode/
java -jar fernflower/build/libs/fernflower.jar \
    ./bluebird/BlueBird-0.0.1-SNAPSHOT.jar \
    BlueBirdSourceCode/
cd BlueBirdSourceCode/
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
```

After `jar -xf`, the `.java` source files are unpacked into `BOOT-INF/classes/com/bmdyy/bluebird/`. All subsequent commands run from inside `BlueBirdSourceCode/`.

### Step 2 — Search for INSERT statements

Rather than opening files one by one, grep for the SQL keyword directly across all decompiled source:

```bash
grep -rn "INSERT" BOOT-INF/classes/ --include="*.java"
```

The `-n` flag includes line numbers so you can jump straight to the relevant code. The `--include="*.java"` filter is critical — without it, grep also searches `.class` binary files and produces garbage output.

**Expected output:**
```
BOOT-INF/classes/com/bmdyy/bluebird/controller/PostController.java:22:         String sql = "INSERT INTO posts (text, author_id, posted_at) VALUES (?, ?, CURRENT_TIMESTAMP);";
BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java:171:                  String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
```

**How to read this output:** Two INSERT statements appear. Read the section after the line number carefully:

- `PostController.java:22` — the query uses `?` placeholders (`VALUES (?, ?, CURRENT_TIMESTAMP)`). These are JDBC `PreparedStatement` parameters: user input is bound separately, never touching the query string. This INSERT is not injectable.
- `AuthController.java:171` — the query builds its `VALUES` clause by string concatenation (`'"+ name +"', '"+ username +"'...`). User-supplied values are stitched directly into the SQL string. This is the vulnerable INSERT.

The file path in the output is the exact path you need for the next step. Copy it from here — do not guess or retype it from memory.

**Why grep before reading:** A real codebase might have hundreds of Java files. Grepping reduces the entire 45 MB JAR to two lines of output in under a second.

### Step 3 — Trace where each variable comes from

The INSERT line names four variables: `name`, `username`, `email`, `passwordHash`. The question is whether each one carries raw user input into the query, or whether something transforms it first. To answer that, look at the code *above* the INSERT, not below it. Use `-B 30` (before) instead of `-A` (after), and target the specific INSERT rather than the generic keyword so you don't pull in the PostController hit:

```bash
grep -B 30 "INSERT INTO users" BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java
```

**Expected output (key sections — `<SNIP>` marks validation logic):**
```java
@PostMapping({"/signup"})
public void signupPOST(@RequestParam String name, @RequestParam String username,
                       @RequestParam String email, @RequestParam String password,
                       HttpServletResponse response) throws IOException {
   if (!name.isEmpty() && !username.isEmpty() && !email.isEmpty() && !password.isEmpty()) {
      <SNIP: duplicate username/email checks using parameterized queries>
               String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
               String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
```

**How to read this output — variable-by-variable:**

- `name`, `username`, `email`, `password` — all declared `@RequestParam` in the method signature. `@RequestParam` means the value comes directly from the HTTP POST body, exactly as the client sent it, with no sanitization. These are user-controlled.
- `password` itself does not appear in the INSERT. The column is named `password` but the value being inserted is `passwordHash`.
- `passwordHash` — defined on the line immediately before the INSERT as `BCrypt.hashpw(password, BCrypt.gensalt(12))`. This is a transformation: whatever value the user sent for `password` is passed through BCrypt before it reaches the SQL string.

### Step 4 — Confirm the transformation that blocks injection

```bash
grep -n "passwordHash\|BCrypt.hashpw" BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java
```

**Expected output:**
```
110:            String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
112:            this.jdbcTemplate.update(sql, new Object[]{passwordHash, Integer.parseInt(uid)});
170:                  String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
171:                  String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
```

There are two occurrences of `passwordHash`. Lines 110–112 are inside a different method (the password reset handler) and use a *parameterized* query (`new Object[]{passwordHash, ...}`) — not relevant here. Lines 170–171 are the ones from `signupPOST`: the `BCrypt.hashpw()` call on 170 feeds directly into the concatenated INSERT on 171.

**Why BCrypt makes `passwordHash` non-injectable:** `BCrypt.hashpw()` always produces a 60-character string in the format `$2b$12$[A-Za-z0-9./]{53}`. The output character set is letters, digits, `.`, `/`, and `$` — none of which are SQL metacharacters. If you submit `password=' OR '1'='1`, BCrypt hashes that input before it reaches the query string. Your single quotes and SQL keywords are gone. The hashing is not a deliberate SQLi defense — it is a side effect of the password storage design — but the result is the same: the value is not injectable.

**Why the other three variables ARE exploitable:** `name`, `username`, and `email` are `@RequestParam` values that flow directly into the `VALUES` clause with zero transformation. Single quotes, dashes, semicolons — anything you send appears literally in the SQL. These become the attack surface in [[labs/htb/advanced_sql_injections/reading_and_writing_files]] and [[labs/htb/advanced_sql_injections/command_execution]].

**Answer: `passwordHash`**

---

## Lessons Learned

- Not every concatenated variable in an unsafe query is exploitable — always trace the variable back to its assignment and look for transformations (encoding, hashing, type conversion) applied before it reaches the query
- BCrypt, by producing output in a restricted character set, acts as an inadvertent SQLi filter — this is a coincidence of design, not intentional defense
- Copy file paths from grep output rather than typing them by hand — the Java package name (`com/bmdyy/bluebird/controller/`) differs from the application name (`bluebird`) and is easy to mistype
- Parameterized queries (`?` placeholders) are immune to injection regardless of input; string concatenation is always the vulnerability to hunt
- Grep for INSERT/UPDATE/SELECT/DELETE before reading source files — it pinpoints injection sinks immediately and saves hours compared to file browsing

## Related Pages

- [[attack/web/white_box_sqli_methodology]] — systematic source review with grep patterns
- [[attack/web/second_order_sqli]] — tracing source/sink pairs
- [[labs/htb/advanced_sql_injections/decompiling_java_archives]] — decompilation prerequisite
- [[labs/htb/advanced_sql_injections/common_character_bypass]] — exploiting the `name`/`username`/`email` fields found here
