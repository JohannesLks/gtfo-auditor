# 🛡️ gtfo-auditor

**Audits sudo rights for GTFO-capable binaries, block evasion, and NOEXEC bypasses.**  
A Red+Blue team tool to verify whether your sudo configuration can withstand real-world privilege escalation attempts.

---

## 🔍 Overview

`gtfo-auditor` simulates attacker techniques derived from [GTFOBins](https://gtfobins.github.io/) to detect:

- ❌ Misconfigured `sudo` rules that unintentionally allow shell escapes
- 🔒 Missing or ineffective `NOEXEC` restrictions
- 🧪 Escalation paths that bypass restricted commands like `zsh`, `bash`, `python`, `vim`, and more
- ✅ Policy confirmations for `BLOCKED`, `ENFORCED`, and `BYPASSED` binaries


---

### 📖 What does “GTFO” mean?

**GTFO** originally stands for *“Get The F\*\*\* Out”* – a phrase from hacker culture used to describe **escaping from a restricted shell or environment**.

In this context, it refers to [GTFOBins](https://gtfobins.github.io/):

> A curated list of Unix binaries that can be used to **bypass restrictions**, **gain shell access**, or **escalate privileges** — especially when misconfigured in `sudo`.

The goal of `gtfo-auditor` is to **simulate these exact escape techniques** and make sure your `sudo` policies **do not allow them**.

---


## 🚀 Features

- 🔄 Fully automated CLI audit
- 🔧 Customizable lists of blocked and NOEXEC-monitored binaries
- 🧠 Execution-based validation (no reliance on `sudo -l` output)
- 🐚 GTFO-style test logic: if a binary can spawn a shell or execute `whoami`, it's flagged
- 📊 Color-coded terminal output with CSV/HTML (optional upcoming) export
- 📦 No dependencies, pure Bash

---

## 🛠️ Installation

```bash
git clone https://github.com/YOURUSERNAME/gtfo-auditor.git
cd gtfo-auditor
chmod +x gtfo-auditor.sh
````

Or copy the script manually.

---

## 🧪 Usage

Audit a specific user:

```bash
sudo ./gtfo-auditor.sh 
```

Example output:

```
Auditing sudo rights for user: test
----------------------------------------------------
COMMAND                  STATE        EXPECTED
/bin/zsh                 BLOCKED      BLOCKED
/usr/bin/vim             NOEXEC       NOEXEC
/usr/bin/python3         BYPASSED     NOEXEC
----------------------------------------------------
Result: VIOLATIONS DETECTED
```

---

## 📁 File Structure

* `gtfo-auditor.sh` – main script
* `ALLOW_NOEXEC` and `ALWAYS_BLOCK` lists are editable inside the script
* Future: exportable `.csv` and `.html` reports

---

## 🔐 Example Policy Use Case

Use `gtfo-auditor` as a CI/CD compliance step or offline audit for:

* Secure bastion hosts
* Developer workstations
* Hardened Docker containers
* Infrastructure nodes in critical zones

---

## ⚠️ Disclaimer

This tool **simulates attacks** using real shell escape techniques. It should be run **as root** (or via `sudo`) on systems you have permission to audit.

---

## 📚 References

* [GTFOBins](https://gtfobins.github.io/)
* [Sudo NOEXEC](https://www.sudo.ws/man/1.8.27/sudoers.man.html#NOEXEC)

---

## 📛 License

MIT License – see `LICENSE` file.

---

## 💬 Contributions Welcome

Got a bypass technique? Add a case block. Found a false negative? File an issue or pull request.

