#!/usr/bin/env python3
import os
import subprocess
import time
from datetime import datetime
import json
import sys
from threading import Thread
from queue import Queue
from colorama import init, Fore, Back, Style
from pathlib import Path

# Инициализация colorama
init(autoreset=True)

# Конфигурация инструментов
TOOLS = {
    'rustscan': {
        'command': 'rustscan -a {target} -- -sC -sV -oN {output_dir}/rustscan.txt',
        'description': 'Быстрое сканирование портов'
    },
    'nmap': {
        'command': 'nmap -sV -sC -oN {output_dir}/nmap.txt {target}',
        'description': 'Подробное сканирование служб'
    },
    'ffuf': {
        'command': 'ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/ffuf.json -of json',
        'description': 'Фаззинг директорий'
    },
    'dirsearch': {
        'command': 'dirsearch -u {target} -e php,asp,aspx,jsp,html,zip,jar -o {output_dir}/dirsearch.txt',
        'description': 'Поиск директорий и файлов'
    },
    'gobuster': {
        'command': 'gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/gobuster.txt',
        'description': 'Поиск директорий (Go)'
    }
}

HEADER_TEMPLATE = "{platforms}: {username}"

def get_output_dir():
    """Определяем путь к директории для отчетов"""
    docs_dir = Path.home() / 'Documents'
    reports_dir = docs_dir / 'K1PLinG_Reports'
    reports_dir.mkdir(exist_ok=True, parents=True)
    return str(reports_dir)

def print_banner():
    banner = f"""
{Fore.RED}{Back.BLACK}
   ▄█   ▄█▄    ▄███████▄  ▄█        ▄█  ███▄▄▄▄      ▄██████▄         
  ███ ▄███▀   ███    ███ ███       ███  ███▀▀▀██▄   ███    ███        
  ███▐██▀     ███    ███ ███       ███▌ ███   ███   ███    █▀         
 ▄█████▀      ███    ███ ███       ███▌ ███   ███  ▄███               
▀▀█████▄    ▀█████████▀  ███       ███▌ ███   ███ ▀▀███ ████▄         
  ███▐██▄     ███        ███       ███  ███   ███   ███    ███        
  ███ ▀███▄   ███        ███▌    ▄ ███  ███   ███   ███    ███        
  ███   ▀█▀  ▄████▀      █████▄▄██ █▀    ▀█   █▀    ████████▀         
  ▀                      ▀                                            
   ▄████████  ▄████████    ▄████████ ███▄▄▄▄   ███▄▄▄▄      ▄████████ 
  ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ ███▀▀▀██▄   ███    ███ 
  ███    █▀  ███    █▀    ███    ███ ███   ███ ███   ███   ███    █▀  
  ███        ███          ███    ███ ███   ███ ███   ███   ███        
▀███████████ ███        ▀███████████ ███   ███ ███   ███ ▀███████████ 
         ███ ███    █▄    ███    ███ ███   ███ ███   ███          ███ 
   ▄█    ███ ███    ███   ███    ███ ███   ███ ███   ███    ▄█    ███ 
 ▄████████▀  ████████▀    ███    █▀   ▀█   █▀   ▀█   █▀   ▄████████▀ 
{Style.RESET_ALL}
{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.YELLOW} K1PLinG SCaNns v2.0 - Advanced Silent Recon Tool            {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE} Automated Vulnerability Scanning with Stealth Mode          {Fore.CYAN}║
{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def run_command(cmd, tool_name, headers=None, output_queue=None):
    start_time = time.time()
    
    if output_queue:
        output_queue.put(f"\n[+] Запуск {tool_name}...")
        output_queue.put(f"[*] Команда: {cmd}")
    
    env = os.environ.copy()
    if headers:
        env.update(headers)
    
    process = subprocess.Popen(
        cmd, 
        shell=True, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        env=env,
        text=True
    )
    
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output and output_queue:
            output_queue.put(output.strip())
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    if output_queue:
        output_queue.put(f"[+] {tool_name} завершен за {elapsed:.2f} сек. Код: {process.returncode}")
    
    return process.returncode

def check_sql_injection(target, headers, output_dir, output_queue):
    if output_queue:
        output_queue.put("\n[+] Проверка на SQL-инъекции...")
    
    test_payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "') OR ('1'='1--",
        "admin'--",
        "1' ORDER BY 1--",
        "1' UNION SELECT null--"
    ]
    
    vulnerable_endpoints = []
    
    for payload in test_payloads:
        test_url = f"{target}?id={payload}"
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' '{test_url}'"
        
        if headers:
            header_str = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {header_str} '{test_url}'"
        
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        status_code = stdout.strip()
        
        if status_code not in ["403", "404", "500"]:
            vulnerable_endpoints.append((test_url, status_code))
            if output_queue:
                output_queue.put(f"[!] Возможная SQL-инъекция: {test_url} (код: {status_code})")
    
    if vulnerable_endpoints:
        with open(f"{output_dir}/sql_injection.txt", "w") as f:
            f.write("Обнаружены возможные SQL-инъекции:\n")
            for url, code in vulnerable_endpoints:
                f.write(f"- URL: {url} (код ответа: {code})\n")
        
        if output_queue:
            output_queue.put("[+] Результаты проверки SQL-инъекций сохранены в sql_injection.txt")
    else:
        if output_queue:
            output_queue.put("[-] SQL-инъекции не обнаружены")

def generate_report(output_dir, target, headers, username, platform, output_queue):
    if output_queue:
        output_queue.put("\n[+] Генерация отчета...")
    
    report = {
        "meta": {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "tester": f"{platform}: {username}",
            "headers": headers
        },
        "tools": {},
        "vulnerabilities": [],
        "recommendations": []
    }
    
    for tool, config in TOOLS.items():
        try:
            if tool == 'ffuf':
                with open(f"{output_dir}/ffuf.json") as f:
                    data = json.load(f)
                    report['tools'][tool] = {
                        "total_requests": data.get("total", 0),
                        "results": [{
                            "url": res['url'],
                            "status": res['status'],
                            "length": res['length']
                        } for res in data.get('results', [])[:10]]
                    }
            else:
                with open(f"{output_dir}/{tool}.txt") as f:
                    report['tools'][tool] = {
                        "output": f.read()[:1000] + "..."
                    }
        except FileNotFoundError:
            report['tools'][tool] = "Файл результатов не найден"
    
    try:
        with open(f"{output_dir}/sql_injection.txt") as f:
            report['vulnerabilities'].append({
                "type": "SQL Injection",
                "details": f.read()
            })
    except FileNotFoundError:
        pass
    
    report['vulnerabilities'].extend([
        {
            "type": "SQL Injection",
            "description": "Позволяет злоумышленнику выполнять произвольные SQL-запросы.",
            "example": f"Уязвимый URL: {target}/product?id=1' OR '1'='1",
            "exploitation": "1. Найдите параметры, уязвимые к SQL-инъекции\n2. Используйте sqlmap для автоматизации\n3. Извлеките данные из БД",
            "mitigation": "Используйте подготовленные запросы (prepared statements)"
        },
        {
            "type": "Directory Traversal",
            "description": "Доступ к файлам вне веб-корня.",
            "example": f"Уязвимый URL: {target}/../../etc/passwd",
            "exploitation": "1. Попробуйте получить доступ к системным файлам\n2. Используйте кодировки для обхода фильтров",
            "mitigation": "Валидируйте входящие пути, используйте whitelist"
        }
    ])
    
    json_path = f"{output_dir}/full_report.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    txt_path = f"{output_dir}/summary_report.txt"
    with open(txt_path, "w") as f:
        f.write(f"Отчет сканирования {target}\n")
        f.write(f"Дата: {report['meta']['date']}\n")
        f.write(f"Тестировщик: {report['meta']['tester']}\n\n")
        
        f.write("=== Результаты инструментов ===\n")
        for tool, data in report['tools'].items():
            f.write(f"\n{tool.upper()}:\n")
            if isinstance(data, dict):
                if 'total_requests' in data:
                    f.write(f"Найдено элементов: {data['total_requests']}\n")
                    f.write("Примеры:\n")
                    for item in data['results']:
                        f.write(f"- {item['url']} (код: {item['status']})\n")
                else:
                    f.write(data.get('output', 'Нет данных') + "\n")
            else:
                f.write(data + "\n")
        
        f.write("\n=== Потенциальные уязвимости ===\n")
        for vuln in report['vulnerabilities']:
            if isinstance(vuln, dict):
                f.write(f"\n{vuln['type']}:\n")
                f.write(f"Описание: {vuln.get('description', '')}\n")
                f.write(f"Пример: {vuln.get('example', '')}\n")
            else:
                f.write(vuln + "\n")
    
    if output_queue:
        output_queue.put(f"[+] Полный отчет сохранен в {json_path}")
        output_queue.put(f"[+] Краткий отчет сохранен в {txt_path}")

def print_output(output_queue):
    while True:
        message = output_queue.get()
        if message == "EXIT":
            break
        print(message)
        sys.stdout.flush()

def get_input(prompt, default=None, required=True):
    while True:
        if default:
            user_input = input(f"{Fore.GREEN}{prompt} [{default}]: {Style.RESET_ALL}").strip()
            if not user_input:
                user_input = default
        else:
            user_input = input(f"{Fore.GREEN}{prompt}: {Style.RESET_ALL}").strip()

        if not required or user_input:
            return user_input
        print(f"{Fore.RED}Это поле обязательно для заполнения!{Style.RESET_ALL}")

def main():
    print_banner()
    
    # Автоматическое определение директории для отчетов
    output_dir = get_output_dir()
    print(f"{Fore.GREEN}[*] Отчеты будут сохранены в: {output_dir}{Style.RESET_ALL}")
    
    target = get_input("Введите целевой URL (например, http://example.com)", required=True)
    username = get_input("Введите ваш ник на платформе bug bounty", required=True)
    platform = get_input("Введите название платформы (например, HackerOne)", required=True)
    
    headers = {
        "User-Agent": HEADER_TEMPLATE.format(platforms=platform, username=username),
        "X-BugBounty": HEADER_TEMPLATE.format(platforms=platform, username=username),
        "From": f"{username}@{platform}.com"
    }
    
    output_queue = Queue()
    print_thread = Thread(target=print_output, args=(output_queue,))
    print_thread.daemon = True
    print_thread.start()
    
    output_queue.put(f"\n[+] Начало сканирования {target}")
    output_queue.put(f"[*] Используемые заголовки: {json.dumps(headers, indent=2)}")
    output_queue.put(f"[*] Результаты будут сохранены в: {output_dir}")
    
    for tool, config in TOOLS.items():
        cmd = config['command'].format(target=target, output_dir=output_dir)
        run_command(cmd, tool, headers, output_queue)
    
    check_sql_injection(target, headers, output_dir, output_queue)
    generate_report(output_dir, target, headers, username, platform, output_queue)
    
    output_queue.put("\n[+] Сканирование завершено!")
    output_queue.put("EXIT")
    print_thread.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано пользователем")
        sys.exit(1)