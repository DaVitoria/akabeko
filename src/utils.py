# utils.py

from collections import defaultdict
import time

# Configuração para detectar um possível ataque DDoS
REQUEST_THRESHOLD = 1000  # Número de requisições que acionam o alerta
TIME_WINDOW = 60  # Janela de tempo em segundos para monitoramento

class DDoSDetector:
    def __init__(self):
        self.request_counts = defaultdict(int)
        self.timestamps = defaultdict(list)

    def log_request(self, ip_address):
        current_time = time.time()
        self.request_counts[ip_address] += 1
        self.timestamps[ip_address].append(current_time)
        self._cleanup(ip_address)

    def _cleanup(self, ip_address):
        # Remove timestamps fora da janela de tempo
        current_time = time.time()
        self.timestamps[ip_address] = [ts for ts in self.timestamps[ip_address] if current_time - ts < TIME_WINDOW]
        self.request_counts[ip_address] = len(self.timestamps[ip_address])

    def check_for_attack(self):
        for ip_address, count in self.request_counts.items():
            if count > REQUEST_THRESHOLD:
                print(f"Possível ataque DDoS detectado de {ip_address}: {count} requisições em {TIME_WINDOW} segundos.")
