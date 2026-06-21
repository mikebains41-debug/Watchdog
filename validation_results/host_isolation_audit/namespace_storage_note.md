# Namespace and Storage Mapping Note

Audit confirms standard Docker isolation primitives:
1. File Layer: overlay2 copy-on-write storage driver.
2. User Space: uid_map shows standard direct root mapping (0 0 4294967295).
Security enforcement relies on the AppArmor profile and cgroup boundaries verified in previous runs.
