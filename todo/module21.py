#!/usr/bin/env python3
"""
Watchdog — Supervisor (B200)
Combines: hardware attestation + remediation + compliance
"""
import subprocess, time, datetime, json, hashlib, hmac as _hmac
import glob, os, sys
from collections import deque

# Safety rails
DRY_RUN = True  # log actions, don't execute
AUTO_REMEDIATION_ENABLED = False  # must be True for any hardware action
HUMAN_APPROVAL_REQUIRED = True  # if True, wait for approval file
APPROVAL_FILE = "/tmp/watchdog_approve_action"
MAX_CONSECUTIVE_ALERTS = 3  # same action must trigger this many times before executing

CORRELATION_WINDOW = 10
ACTION_COOLDOWN = 60
PROOF_INTERVAL = 3600
HMAC_KEY_FILE = "/tmp/watchdog_hmac.key"
LOG_DIR = "."

LEVEL_WARN = 1
LEVEL_RESET = 2
LEVEL_QUARANTINE = 3

# ... rest of module21.py code here ...
