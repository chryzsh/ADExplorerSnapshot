# AI Agent Guidelines

Guidelines for AI agents (Claude Code, Copilot, Cursor, etc.) working in this repository.

## Workflow

1. **Read before writing.** Understand existing code, patterns, and conventions before making changes.
2. **Commit after each logical change.** Don't batch unrelated changes into one commit.
3. **Update documentation after each change.** If you add or modify scripts, flags, or behavior, update the README and any relevant docs in the same commit or immediately after.
4. **Test when possible.** Run scripts or tests to verify changes work before committing.

## Commit messages

- Use imperative mood in the subject line ("Add feature", not "Added feature")
- Keep the subject under 72 characters
- Use the body to explain *what* and *why*, not *how*
- Include `Co-Authored-By` trailer when appropriate

## Code conventions

- Scripts in `scripts/` are standalone utilities that import `adexpsnapshot` as a library
- All scripts should include the `sys.path` fix so they can be run from any directory:
  ```python
  import sys, os
  sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
  ```
- Use `argparse` for argument parsing (not raw `sys.argv`)
- Support `-o` for output (file or folder depending on the script)
- Use `bloodhound.ad.utils.ADUtils` for AD attribute access

## Project structure

- `adexpsnapshot/` — core library (snapshot parser, BloodHound/BOFHound output)
- `scripts/` — standalone dump utilities (not imported by the main tool)
- `scripts/run_all.py` — wrapper to run all dump scripts with structured output
- `ADExplorerSnapshot.py` — main entry point

## What to avoid

- Don't modify the core parser (`adexpsnapshot/`) without understanding the snapshot binary format
- Don't add dependencies without checking if they're optional (some scripts depend on `certipy`, `adidnsdump`)
- Don't break backward compatibility of CLI arguments
