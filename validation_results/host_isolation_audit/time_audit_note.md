# Time/Clock Audit Note

RTC device file (/dev/rtc) is hidden - clean. However /proc/uptime
reveals the physical host's uptime (~387 days), not the container's
own uptime, and /proc/driver/rtc is readable, exposing host RTC
hardware status (time, alarm settings, battery status). Consistent
with the broader pattern: low-sensitivity host platform metadata
leaks through /proc, but no tenant workload data or other-tenant
information is exposed.
