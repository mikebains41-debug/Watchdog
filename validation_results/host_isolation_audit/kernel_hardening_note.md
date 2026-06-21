# Kernel Hardening Note

ASLR (randomize_va_space) = 2: fully enabled, strongest setting.
max_map_count = 65530: standard Linux default. Both clean - no
hardening deficiencies found at the kernel memory-protection layer.
