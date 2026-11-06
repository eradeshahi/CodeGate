---
name: codegate
description: Use the CodeGate MCP server to read, search, edit and test code on the user's machine within the directories they allowed. Trigger when CodeGate tools (allowed_directories, get_file_text_by_path, replace_text_in_file, run_command, ...) are available and the task involves exploring a codebase, changing files, checking git state or running tests/builds.
---

# CodeGate

CodeGate is a self-hosted MCP server that exposes a sandboxed slice of the user's file system. Every path is checked against per-directory permissions (`read`, `write`, `execute`, `full`). Secrets (`.env`, keys, `.git/config`, ...) and usually dot-files are always denied.

## 1. Orient first

1. Call `allowed_directories` to learn the roots you may touch, then `directory_permissions` to see what each allows.
2. Work only inside those roots. If you get a permission error, don't try other spellings of the path, `..`, symlinks or shell commands to get around it. Tell the user which path or permission is missing so they can update `config.json`.
3. Get an overview with `list_directory_tree` (keep `max_depth` at 2–3). Heavy folders like `node_modules`, `vendor` and `.git` are skipped automatically.

## 2. Find things

| Need | Tool |
| --- | --- |
| Files by pattern (`**/*.py`, `app/**/*Controller.php`) | `find_files_by_glob` |
| Files/folders whose name contains a word | `find_files_by_name_keyword` |
| Code containing text or a regex | `search_in_files_by_text` (`regex`, `case_sensitive`, `context_lines`, narrow with `glob_pattern`) |
| Size, line count, line endings, BOM | `file_info` |

Narrow searches with `base_dir` and `glob_pattern` rather than searching a whole root. Results are capped by `limits.max_list_items`.

## 3. Read before you edit

- Use `get_file_text_by_path`. For large files, read in chunks with `offset`/`limit`. A note tells you when more lines remain.
- Pass `line_numbers=true` while you're locating code, but **never copy the line-number prefixes into `old_text`**.

## 4. Edit safely

- `replace_text_in_file`: `old_text` must match exactly, including indentation, and be unique. If it isn't unique, add surrounding lines, or set `replace_all=true` only when you really mean every occurrence.
- `multi_edit`: several changes to one file, applied in order, all or nothing. Each `old_text` is matched against the result of the previous edit. Prefer this to a series of single replacements.
- `create_new_file`: new files only. Use `overwrite=true` only when you intend to replace the whole file. Prefer targeted edits for existing files.
- `move_file`: rename or move. It never overwrites the destination.
- Every edit returns a unified diff. Check it before moving on. Line endings (LF/CRLF) and BOM are preserved, so don't normalize them yourself.

## 5. Git (read-only)

`git_status`, `git_diff` (`staged`, `file`) and `git_log` let you review your changes and the history. CodeGate cannot commit, push or check out. Hand those steps to the user.

## 6. Run commands

- `run_command` takes an executable plus an `args` list. It runs without a shell, so pipes, `&&`, redirects and globs won't work.
- Only allowlisted commands run, typically test runners and build tools such as `npm test` or `php artisan test`. Inline code (`python -c`, `node -e`, `php -r`) and destructive commands are blocked.
- Set `cwd` to the project folder (it needs `execute` permission). Use `timeout_seconds` for slow suites.
- If a command is refused, don't try to sneak it in another way. Tell the user it needs to be added to `commands.allowlist`.

## Typical loop

`allowed_directories` → `list_directory_tree` → `search_in_files_by_text` → `get_file_text_by_path` → `multi_edit` / `replace_text_in_file` → `run_command` (tests) → `git_diff` → summarize the changes for the user.
