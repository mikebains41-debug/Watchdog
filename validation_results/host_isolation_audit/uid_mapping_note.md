# UID Mapping Note

/proc/self/uid_map shows "0 0 4294967295" - UID 0 inside the
container maps directly to UID 0 on the host. No user namespace
remapping in use. This is standard for most Docker-based GPU cloud
platforms (not unique to Vast.ai); userns-remap is an optional
hardening feature most providers don't enable since it can interfere
with GPU device passthrough. Implication: a container-escape exploit
would grant host root, which is the standard risk model across the
industry, not a Vast.ai-specific misconfiguration.
