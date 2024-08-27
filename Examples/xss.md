import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from src.scan import sql_injection_scan

# Configuração do User-Agent
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

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
    # Payloads de XSS comuns para teste
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
    ]
    if response:
        content = response.content.decode().lower()
        for payload in payloads:
            if payload in content:
                return True
    return False

def xss_scan(url):
    forms = get_forms(url)
    print(f"[+] Detectado {len(forms)} formulários em {url}.")

    for form in forms:
        details = form_details(form)
        action = details["action"]
        method = details["method"]
        inputs = details["inputs"]
        
        # Construir a URL completa para o formulário
        form_url = urljoin(url, action) if action else url

        for payload in ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"]:
            data = {}
            for input_tag in inputs:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + payload
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = payload

            try:
                if method == "post":
                    res = s.post(form_url, data=data)
                elif method == "get":
                    res = s.get(form_url, params=data)
                else:
                    print(f"Método de formulário desconhecido: {method}")
                    continue
                
                if vulnerable(res):
                    print("Vulnerabilidade XSS detectada no site:", url)
                    return  # Interromper a execução se vulnerabilidades forem encontradas
            except requests.exceptions.RequestException as e:
                print(f"Erro ao enviar o formulário: {e}")

    print("Nenhuma vulnerabilidade XSS foi detectada!")

if __name__ == "__main__":
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
                print("\n\tFuncionalidade DDoS ainda em desenvolvimento...")
            else:
                print("\n\tOpção selecionada é inválida!")
        
        except ValueError:
            print("\n\tEntrada inválida! Por favor, selecione um número válido.")

        print("\n" + "-" * 50)
