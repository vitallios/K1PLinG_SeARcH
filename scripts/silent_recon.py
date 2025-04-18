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
        'command': 'ffuf -u {target}/FUZZ -w /app/wordlists/common.txt -o {output_dir}/ffuf.json -of json',
        'description': 'Фаззинг директорий'
    },
    'dirsearch': {
        'command': 'python /opt/dirsearch/dirsearch.py -u {target} -e php,asp,aspx,jsp,html,zip,jar -o {output_dir}/dirsearch.txt',
        'description': 'Поиск директорий и файлов'
    },
    'gobuster': {
        'command': 'gobuster dir -u {target} -w /app/wordlists/common.txt -o {output_dir}/gobuster.txt',
        'description': 'Поиск директорий (Go)'
    }
}

HEADER_TEMPLATE = "{platforms}: {username}"

def print_banner():
    banner = f"""
{Fore.RED}{Back.BLACK}
███████╗ █████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗██████╗ 
██╔════╝██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗
███████╗███████║███████╗██║   ██║█████╗  ██████╔╝█████╗  ██████╔╝
╚════██║██╔══██║╚════██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
███████║██║  ██║███████║ ╚████╔╝ ███████╗██║  ██║███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.YELLOW} K1PLinG SeARcH v2.0 - Silent Recon Tool for Bug Bounty      {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE} Автоматизированное сканирование уязвимостей с тихим режимом {Fore.CYAN}║
{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

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

[... остальная часть скрипта остается без изменений ...]