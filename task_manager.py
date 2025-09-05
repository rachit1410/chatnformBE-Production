#!/usr/bin/env python
import sys
from django.core.management import execute_from_command_line

def run_command(command_name):
    """Runs a Django management command"""
    execute_from_command_line([sys.argv[0], command_name])

if __name__ == "__main__":
    # Example usage:
    # python task_manager.py kafka
    # python task_manager.py cleanup
    if len(sys.argv) < 2:
        print("Specify a command: kafka | cleanup")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "kafka":
        run_command("run_kafka_consumer")
    elif cmd == "cleanup":
        run_command("eat_my_old_files_cron")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
