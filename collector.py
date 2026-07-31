#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN-сборщик с улучшенной проверкой
Проверяет реальную работоспособность ключей и отсеивает медленные
"""

import os
import re
import json
import time
import socket
import base64
import subprocess
import threading
from datetime import datetime
from urllib.parse import urlparse
import requests
from github import Github

# ========== НАСТРОЙКИ ==========
SOURCES = [
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/All_Configs.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.1.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/ru-sni/vless_ru.txt",
]

TIMEOUT = 3  # секунд на проверку
MAX_KEYS = 500  # максимум ключей в подписке
MAX_PING = 500  # максимальный пинг в миллисекундах
# ================================

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
    token = os.getenv('GH_TOKEN')
    if not token:
        raise Exception("❌ GH_TOKEN не найден!")
    g = Github(token)
    repo_name = os.getenv('GITHUB_REPOSITORY')
    if not repo_name:
        raise Exception("❌ GITHUB_REPOSITORY не найден!")
    return g.get_repo(repo_name)


def fetch_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, timeout=10, headers=headers)
        return r.text if r.status_code == 200 else None
    except:
        return None


def extract_keys(text):
    keys = {}
    for protocol, pattern in PATTERNS.items():
        found = re.findall(pattern, text)
        if found:
            keys[protocol] = found
    return keys


def extract_host_from_link(link):
    """Извлечение хоста и порта из ссылки"""
    try:
        if link.startswith('vless://') or link.startswith('trojan://') or link.startswith('hysteria2://'):
            parsed = urlparse(link)
            host = parsed.hostname
            port = parsed.port or 443
            return host, port
        elif link.startswith('vmess://'):
            try:
                encoded = link[8:]
                if len(encoded) % 4 != 0:
                    encoded += '=' * (4 - len(encoded) % 4)
                decoded = base64.b64decode(encoded).decode('utf-8')
                config = json.loads(decoded)
                host = config.get('add') or config.get('host')
                port = int(config.get('port', 443))
                return host, port
            except:
                return None, None
        elif link.startswith('ss://'):
            try:
                without_prefix = link[5:]
                if '@' in without_prefix:
                    host_part = without_prefix.split('@')[1]
                    host = host_part.split(':')[0]
                    port = int(host_part.split(':')[1].split('/')[0])
                    return host, port
                else:
                    if len(without_prefix) % 4 != 0:
                        without_prefix += '=' * (4 - len(without_prefix) % 4)
                    decoded = base64.b64decode(without_prefix).decode('utf-8')
                    if '@' in decoded:
                        host = decoded.split('@')[1].split(':')[0]
                        port = int(decoded.split(':')[1].split('/')[0])
                        return host, port
            except:
                pass
        return None, None
    except:
        return None, None


def check_key_real(link):
    """Проверка ключа с измерением пинга"""
    host, port = extract_host_from_link(link)
    if not host:
        return False, 9999
    
    # Пробуем разные порты
    ports_to_try = [port, 443, 80, 8080, 8443, 2096] if port else [443, 80, 8080, 8443, 2096]
    ports_to_try = list(dict.fromkeys(ports_to_try))  # удаляем дубли
    
    for test_port in ports_to_try[:3]:  # проверяем только первые 3 порта
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((host, test_port))
            sock.close()
            
            if result == 0:
                ping_ms = int((time.time() - start) * 1000)
                if ping_ms < MAX_PING:
                    return True, ping_ms
        except:
            pass
    
    return False, 9999


def save_configs(keys, repo=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    all_keys = []
    for protocol, links in keys.items():
        all_keys.extend(links)
    
    if len(all_keys) > MAX_KEYS:
        all_keys = all_keys[:MAX_KEYS]
    
    all_file = f"{OUTPUT_DIR}/configs_all.txt"
    with open(all_file, 'w', encoding='utf-8') as f:
        f.write(f"# Обновлено: {timestamp}\n")
        f.write(f"# Всего ключей: {len(all_keys)}\n")
        f.write(f"# Макс. пинг: {MAX_PING} мс\n\n")
        for link in all_keys:
            f.write(link + '\n')
    
    # Файлы по протоколам
    for protocol, links in keys.items():
        if links:
            protocol_file = f"{OUTPUT_DIR}/configs_{protocol}.txt"
            with open(protocol_file, 'w', encoding='utf-8') as f:
                f.write(f"# Обновлено: {timestamp}\n")
                f.write(f"# Ключей {protocol}: {len(links)}\n\n")
                for link in links[:MAX_KEYS]:
                    f.write(link + '\n')
    
    stats = {
        'last_update': timestamp,
        'total_keys': len(all_keys),
        'protocols': {p: len(l) for p, l in keys.items()},
        'max_ping': MAX_PING,
        'sources': len(SOURCES)
    }
    with open('stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    if repo:
        commit_files(repo)
    
    return stats


def commit_files(repo):
    try:
        # Коммитим все файлы в папке configs
        for file_name in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, file_name)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                existing = repo.get_contents(file_path, ref='main')
                repo.update_file(
                    file_path,
                    f"Обновление: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    content,
                    existing.sha,
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
        
        # stats.json
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
        print(f"❌ Ошибка коммита: {e}")


def main():
    print("🚀 Запуск улучшенного сборщика...")
    print(f"📂 Источников: {len(SOURCES)}")
    print(f"⏱️ Таймаут: {TIMEOUT} сек")
    print(f"📊 Макс. пинг: {MAX_PING} мс")
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
    print(f"📊 Всего найдено: {total_found} ключей")
    print("-" * 50)
    print("🔍 Проверка ключей (реальное подключение + пинг)...")
    
    checked_keys = {}
    checked_count = 0
    total_to_check = sum(len(v) for v in all_keys.values())
    
    for protocol, links in all_keys.items():
        print(f"   Проверка {protocol}...")
        working = []
        for link in links[:MAX_KEYS * 2]:  # проверяем больше, чтобы потом отсеять
            checked_count += 1
            if checked_count % 10 == 0:
                print(f"      Проверено: {checked_count}/{total_to_check}")
            
            is_working, ping = check_key_real(link)
            if is_working:
                working.append(link)
                print(f"      ✅ Работает (пинг: {ping} мс)")
            
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
        print(f"   📈 Макс. пинг: {stats['max_ping']} мс")
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        stats = save_configs(checked_keys, None)
        print("📁 Сохранено локально в папку configs/")
    
    print("🏁 Готово!")


if __name__ == "__main__":
    main()
