from datetime import datetime, timedelta
import time
import threading

class Scheduler:
    def __init__(self):
        self.tasks = []

    def add_task(self, task, interval):
        next_run = datetime.now() + timedelta(seconds=interval)
        self.tasks.append((task, next_run, interval))

    def run(self):
        while True:
            now = datetime.now()
            for task, next_run, interval in self.tasks:
                if now >= next_run:
                    threading.Thread(target=task).start()
                    next_run = now + timedelta(seconds=interval)
            time.sleep(1)

    def start(self):
        threading.Thread(target=self.run).start()