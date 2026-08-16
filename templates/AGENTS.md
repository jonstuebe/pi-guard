# Pi Guard development environment

- Model-controlled shell and filesystem operations run in a Gondolin Linux VM.
- The host project is mounted at `/workspace`; writes under allowed paths persist to the host.
- Sensitive files and paths may appear not to exist because policy hides them.
- Network access is denied unless the user configured specific hosts.
- Host commands are exposed as named structured operations and require user approval.
- If a tool is blocked, do not search for a bypass. Report the blocked operation and reason.
- A rejected host operation is blocked; do not assume it ran in another environment.
