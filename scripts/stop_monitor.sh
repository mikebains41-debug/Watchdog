#!/bin/bash
pkill -f "keep_running.sh" && echo "Monitor stopped." || echo "No monitor running."
