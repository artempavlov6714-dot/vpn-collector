#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN-сборщик и проверщик ключей
Собирает ключи из открытых источников, проверяет их и сохраняет в репозиторий
"""

import os
import re
import json
import time
import socket
import base64
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests
from github import Github, GithubException

# ========== НАСТРОЙКИ ==========
SOURCES = [
    # GitHub-репозитории с конфигами
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/All_Configs.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.1.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/ru-sni/vless_ru.txt",
]

TIMEOUT = 5  # секунд на проверку ключа
MAX_KEYS = 500  # максимальное количество ключей в финальной подписке
# ================================

# Паттерны для поиска ключей
PATTERNS = {
    'vless': r'vless://[A-Za-z0-9+/?=._%-]+',
    'vmess': r'vmess://[A-Za-z0-9+/?=._%-]+',
    'trojan': r'trojan://[A-Za-z0-9+/?=._%-]+',
    'ss': r'ss://[A-Za-z0-9+/?=._%-]+',
    'hysteria2': r'hysteria2://[A-Za-z0-9+/?=._%-]+',
}

OUTPUT_DIR = "configs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_github_repo():
    """Подключение к GitHub репозиторию"""
    token = os.getenv('GH_TOKEN')
    if not token:
        raise Exception("❌ GH_TOKEN не найден! Добавьте секрет в репозиторий.")
    
    g = Github(token)
    repo_name = os.getenv('GITHUB_REPOSITORY')
    if not repo_name:
        raise Exception("❌ GITHUB_REPOSITORY не найден! Запускайте через GitHub Actions.")
    
    return g.get_repo(repo_name)


def fetch_content(url):
    """Загрузка содержимого по URL"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=10, headers=headers)
        if response.status_code == 200:
            return response.text
        return None
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {url}: {e}")
        return None


def extract_keys(text):
    """Извлечение всех ключей из текста"""
    keys = {}
    for protocol, pattern in PATTERNS.items():
        found = re.findall(pattern, text)
        if found:
            keys[protocol] = found
    return keys


def decode_vmess_config(link):
    """Декодирование vmess ссылки для получения информации"""
    try:
        if link.startswith('vmess://'):
            encoded = link[8:]
            if len(encoded) % 4 != 0:
                encoded += '=' * (4 - len(encoded) % 4)
            decoded = base64.b64decode(encoded).decode('utf-8')
            config = json.loads(decoded)
            return config.get('add', '') or config.get('host', '')
    except:
        pass
    return None


def extract_host_from_link(link):
    """Извлечение хоста из ссылки для проверки"""
    try:
        if link.startswith('vless://') or link.startswith('trojan://') or link.startswith('hysteria2://'):
            parsed = urlparse(link)
            return parsed.hostname
        elif link.startswith('vmess://'):
            return decode_vmess_config(link)
        elif link.startswith('ss://'):
            try:
                without_prefix = link[5:]
                if '@' in without_prefix:
                    host_part = without_prefix.split('@')[1]
                    host = host_part.split(':')[0]
                    return host
                else:
                    if len(without_prefix) % 4 != 0:
                        without_prefix += '=' * (4 - len(without_prefix) % 4)
                    decoded = base64.b64decode(without_prefix).decode('utf-8')
                    if '@' in decoded:
                        host = decoded.split('@')[1].split(':')[0]
                        return host
            except:
                pass
        return None
    except:
        return None


def check_host_alive(host, port=443):
    """Проверка доступности хоста через TCP-соединение"""
    if not host:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def check_key(link):
    """Проверка ключа на работоспособность"""
    host = extract_host_from_link(link)
    if host:
        return check_host_alive(host)
    return False


def save_configs(keys, repo=None):
    """Сохранение ключей в репозиторий"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    all_keys = []
    for protocol, links in keys.items():
        all_keys.extend(links)
    
    if len(all_keys) > MAX_KEYS:
        all_keys = all_keys[:MAX_KEYS]
    
    output_files = {}
    
    # Общий файл
    all_file = f"{OUTPUT_DIR}/configs_all.txt"
    with open(all_file, 'w', encoding='utf-8') as f:
        f.write(f"# Обновлено: {timestamp}\n")
        f.write(f"# Всего ключей: {len(all_keys)}\n\n")
        for link in all_keys:
            f.write(link + '\n')
    output_files['all'] = all_file
    
    # Файлы по протоколам
    for protocol, links in keys.items():
        if links:
            protocol_file = f"{OUTPUT_DIR}/configs_{protocol}.txt"
            with open(protocol_file, 'w', encoding='utf-8') as f:
                f.write(f"# Обновлено: {timestamp}\n")
                f.write(f"# Ключей {protocol}: {len(links)}\n\n")
                for link in links[:MAX_KEYS]:
                    f.write(link + '\n')
            output_files[protocol] = protocol_file
    
    # Статистика
    stats = {
        'last_update': timestamp,
        'total_keys': len(all_keys),
        'protocols': {p: len(l) for p, l in keys.items()},
        'sources': len(SOURCES)
    }
    with open('stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    if repo:
        commit_files(repo, output_files)
    
    return stats


def commit_files(repo, files):
    """Коммит файлов в репозиторий"""
    try:
        branch = repo.get_branch('main')
        
        for file_path in files.values():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                try:
                    existing_file = repo.get_contents(file_path, ref='main')
                    repo.update_file(
                        file_path,
                        f"Обновление конфигов: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                        content,
                        existing_file.sha,
                        branch='main'
                    )
                    print(f"✅ Обновлён: {file_path}")
                except:
                    repo.create_file(
                        file_path,
                        f"Создание: {file_path}",
                        content,
                        branch='main'
                    )
                    print(f"✅ Создан: {file_path}")
            except Exception as e:
                print(f"⚠️ Ошибка с {file_path}: {e}")
        
        try:
            with open('stats.json', 'r', encoding='utf-8') as f:
                stats_content = f.read()
            try:
                existing_stats = repo.get_contents('stats.json', ref='main')
                repo.update_file(
                    'stats.json',
                    f"Обновление статистики: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    stats_content,
                    existing_stats.sha,
                    branch='main'
                )
                print("✅ Обновлена статистика")
            except:
                repo.create_file(
                    'stats.json',
                    "Создание статистики",
                    stats_content,
                    branch='main'
                )
                print("✅ Создана статистика")
        except Exception as e:
            print(f"⚠️ Ошибка статистики: {e}")
            
    except Exception as e:
        print(f"❌ Ошибка коммита: {e}")


def main():
    """Основная функция"""
    print("🚀 Запуск VPN-сборщика...")
    print(f"📂 Источников: {len(SOURCES)}")
    print(f"⏱️ Таймаут проверки: {TIMEOUT} сек")
    print(f"🔢 Максимум ключей: {MAX_KEYS}")
    print("-" * 50)
    
    all_keys = {}
    total_found = 0
    
    for source in SOURCES:
        print(f"📥 Загрузка: {source}")
        content = fetch_content(source)
        if content:
            keys = extract_keys(content)
            for protocol, links in keys.items():
                if protocol not in all_keys:
                    all_keys[protocol] = []
                for link in links:
                    if link not in all_keys[protocol]:
                        all_keys[protocol].append(link)
                total_found += len(links)
            print(f"   ✅ Найдено: {sum(len(k) for k in keys.values())} ключей")
        else:
            print(f"   ❌ Не загружено")
        time.sleep(1)
    
    print("-" * 50)
    print(f"📊 Всего найдено уникальных ключей: {total_found}")
    for protocol, links in all_keys.items():
        print(f"   {protocol}: {len(links)}")
    
    print("-" * 50)
    print("🔍 Проверка ключей на работоспособность...")
    
    checked_keys = {}
    checked_count = 0
    
    for protocol, links in all_keys.items():
        print(f"   Проверка {protocol}...")
        working = []
        for link in links:
            checked_count += 1
            if checked_count % 20 == 0:
                print(f"      Проверено: {checked_count} / {total_found}")
            
            if check_key(link):
                working.append(link)
            
            time.sleep(0.2)
        
        if working:
            checked_keys[protocol] = working
            print(f"      ✅ {protocol}: {len(working)} рабочих из {len(links)}")
        else:
            print(f"      ❌ {protocol}: 0 рабочих")
    
    print("-" * 50)
    
    try:
        repo = get_github_repo()
        stats = save_configs(checked_keys, repo)
        print("✅ Результаты сохранены в репозиторий!")
        print(f"   📅 Обновлено: {stats['last_update']}")
        print(f"   📊 Всего: {stats['total_keys']} ключей")
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        stats = save_configs(checked_keys, None)
        print("📁 Сохранено локально в папку configs/")
    
    print("🏁 Готово!")


if __name__ == "__main__":
    main()
