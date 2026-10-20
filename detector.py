
from collections import defaultdict, deque
from datetime import datetime, timedelta
import re
import csv

LOG_FILE = "auth.log"
THRESHOLD = 5
WINDOW_SECONDS = 60


def detect_brute_force(log_file):
    failed_attempts = defaultdict(list)

    pattern = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?"
        r"Failed login from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for line in file:
                match = pattern.search(line)

                if match:
                    timestamp = datetime.strptime(
                        match.group("timestamp"),
                        "%Y-%m-%d %H:%M:%S"
                    )
                    ip = match.group("ip")
                    failed_attempts[ip].append(timestamp)

    except FileNotFoundError:
        print(f"Erreur : fichier {log_file} introuvable.")
        return

    print("\n=== BRUTE FORCE DETECTION SYSTEM ===")
    print(f"Seuil : {THRESHOLD} echecs en {WINDOW_SECONDS} secondes\n")

    report = []
    alerts_found = False

    for ip, attempts in sorted(failed_attempts.items()):
        attempts.sort()
        queue = deque()
        max_attempts = 0
        alert_time = None

        for timestamp in attempts:
            queue.append(timestamp)

            while (
                queue
                and (timestamp - queue[0]).total_seconds() > WINDOW_SECONDS
            ):
                queue.popleft()

            if len(queue) > max_attempts:
                max_attempts = len(queue)

            if len(queue) >= THRESHOLD and alert_time is None:
                alert_time = timestamp

        status = (
            "SUSPICIOUS"
            if alert_time is not None
            else "NORMAL"
        )

        report.append([ip, len(attempts), max_attempts, status])

        if status == "SUSPICIOUS":
            alerts_found = True
            print(f"[ALERTE] IP suspecte : {ip}")
            print(f"  Nombre total d'echecs : {len(attempts)}")
            print(f"  Maximum en {WINDOW_SECONDS}s : {max_attempts}")
            print(f"  Alerte declenchee : {alert_time}\n")

    if not alerts_found:
        print("Aucune activite suspecte detectee.")

    with open("report.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "IP", "Total failed attempts",
            "Maximum in time window", "Status"
        ])
        writer.writerows(report)

    print("Rapport exporte dans report.csv")


if __name__ == "__main__":
    detect_brute_force(LOG_FILE)
