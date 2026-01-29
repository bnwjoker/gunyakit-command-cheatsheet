# Copilot instructions

## Project overview
- This repo is a markdown-based command cheat sheet for security/ops tasks.
- Content is organized by numbered domains and subtopics (e.g., scanning, AD, privilege escalation, OS commands).
- The canonical index is [README.md](README.md) with a Table of Contents linking into topic files.

## Structure to follow
- Top-level sections are numbered folders: [1.Scanning/](1.Scanning/), [2.CVE-Exploit/](2.CVE-Exploit/), [3.AD-Exploit/](3.AD-Exploit/), [4.Privilege-Escalation/](4.Privilege-Escalation/), [5.Lataral-Movement/](5.Lataral-Movement/), [6.OS-Command/](6.OS-Command/).
- Topic files use numbered filenames that match their folder ordering (example: [1.Scanning/1.Port-Scanning.md](1.Scanning/1.Port-Scanning.md)).
- When adding or renaming files, keep the README Table of Contents in sync with the new paths.

## Content conventions (examples are authoritative)
- Each topic file starts with an H1 title and a “Table of Contents” section (see [1.Scanning/1.Port-Scanning.md](1.Scanning/1.Port-Scanning.md) and [6.OS-Command/6.1.Windows-command.md](6.OS-Command/6.1.Windows-command.md)).
- Use short descriptive subsections (H2/H3/H4) with bullet lists for tasks and commands.
- Commands are shown in fenced code blocks, usually tagged as `shell`. Some blocks are untagged; follow the local pattern in the file you’re editing.
- Use placeholder variables like `$rhost`, `$cidr` in command snippets as shown in [1.Scanning/1.Port-Scanning.md](1.Scanning/1.Port-Scanning.md).
- Use blockquotes for short notes or scan descriptions (e.g., “> 1000 Port scan” in [1.Scanning/1.Port-Scanning.md](1.Scanning/1.Port-Scanning.md)).

## Workflows
- No build/test tooling is defined in this repo; changes are markdown-only.
- Prefer minimal edits scoped to the relevant topic file and update README links if you change paths.
