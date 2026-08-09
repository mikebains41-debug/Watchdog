.PHONY: install run health status start stop logs clean

install:
./scripts/install_deps.sh

run:
python3 run_all.py

health:
./health_check.sh

status:
./scripts/status.sh

start:
./scripts/start_monitor.sh

stop:
./scripts/stop_monitor.sh

logs:
tail -f watchdog_auto.log

clean:
rm -f watchdog_output.jsonl nohup.out watchdog_auto.log *.jsonl
