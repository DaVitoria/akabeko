import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from src.xss import xss_scan
from collections import defaultdict
import time

# Configuração do User-Agent
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

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

def get_forms(url):
    # Adicionar o esquema à URL se estiver faltando
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = s.get(url)
        response.raise_for_status()  # Lançar exceção para status de erro HTTP
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar o URL: {e}")
        return []

def form_details(form):
    details_of_form = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    
    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

def vulnerable(response):
    errors = [
        "a sequência das aspas não combina",
        "aviso: mysql",
        "aspas não fechadas após a sequência dos caracteres",
        "você tem um erro na syntax de sql"
    ]
    if response:
        content = response.content.decode().lower()
        return any(error in content for error in errors)
    return False

def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detectado {len(forms)} formulários em {url}.")

    for form in forms:
        details = form_details(form)
        action = details["action"]
        method = details["method"]
        inputs = details["inputs"]
        
        # Construir a URL completa para o formulário
        form_url = urljoin(url, action) if action else url

        for i in "\"'":
            data = {}
            for input_tag in inputs:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"Testando{i}"

            try:
                if method == "post":
                    res = s.post(form_url, data=data)
                elif method == "get":
                    res = s.get(form_url, params=data)
                else:
                    print(f"Método de formulário desconhecido: {method}")
                    continue
                
                if vulnerable(res):
                    print("Existem vulnerabilidades de SQL Injection no site:", url)
                    return  # Interromper a execução se vulnerabilidades forem encontradas
            except requests.exceptions.RequestException as e:
                print(f"Erro ao enviar o formulário: {e}")

    print("Nenhuma vulnerabilidade de SQL Injection foi detectada!")

if __name__ == "__main__":
    ddos_detector = DDoSDetector()

    while True:
        print("\n\t\t============== Agente de Teste de Vulnerabilidades ==============")
        print("\n\n\t\t=================== Seja Bem Vindo ==================")
        print("\nO presente programa visa auxiliar os seus usuários a realizarem testes de vulnerabilidades nos seus sites ou sistemas")
        print("\n\n\n\t\t\t1 - SQL Injection\n\t\t\t2 - XSS\n\t\t\t3 - DDoS")
        
        opcao = input("\n\tSelecione a Opção\n\t>>>>>: ")
        
        try:
            opc = int(opcao)
            
            if opc == 1:
                urlCheck = input("\n\tDigite o link a ser verificado: ")
                sql_injection_scan(urlCheck)
            elif opc == 2:
                urlCheck = input("\n\tDigite o link a ser verificado: ")
                xss_scan(urlCheck)
            elif opc == 3:
                print("\n\tIniciando detecção de DDoS...")
                while True:
                    ip = input("\nDigite o IP que fez a requisição (ou 'sair' para encerrar): ")
                    if ip.lower() == 'sair':
                        break
                    ddos_detector.log_request(ip)
                    ddos_detector.check_for_attack()
            else:
                print("\n\tOpção selecionada é inválida!")
        
        except ValueError:
            print("\n\tEntrada inválida! Por favor, selecione um número válido.")

        print("\n" + "-" * 50)
