# Фильтр DNS с использованием NFQUEUE
## Описание проекта

Программа представляет собой фильтр DNS трафика, работающий через механизм NFQUEUE в Linux. Фильтр анализирует DNS пакеты и применяет правила для блокировки или пропуска запросов на основе различных полей DNS протокола.

Основные возможности:
- Фильтрация по доменным именам (с поддержкой регулярных выражений)
- Фильтрация по типу DNS запроса (A, AAAA, MX, TXT и др.)
- Чтение правил из конфигурационного файла
- Поддержка действий: drop (удаление) и pass (пропуск)
- Логирование всех операций в реальном времени

Поддерживаемые поля DNS для фильтрации:
- `qname` - доменное имя (с регулярными выражениями)
- `qtype` - тип DNS запроса (A, AAAA, MX, TXT, NS, CNAME)
- `src_ip` - IP-адрес источника
- `dst_ip` - IP-адрес назначения
- `qr` - тип пакета (запрос/ответ)

Требования:
- Python 3.6+
- Библиотеки: netfilterqueue, scapy
- Linux с поддержкой NFQUEUE
- Доступ root для работы с iptables


## Запуск программы
1. **Настройка iptables**

```
iptables -t mangle -F
iptables -t mangle -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 5
iptables -t mangle -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 5
```

2. **Создание файла с правилами**

Создайте файл dns_rules.txt:
```
qname matches ".*malicious\.com" drop
qname matches "ads\.com" drop
qname matches "tracker\.com" drop
qname matches "google\.com" pass
qname matches "ya\.ru" pass
qname matches "good-site\.com" pass
qtype == "A" pass
qtype == "AAAA" pass
qtype == "MX" drop
qtype == "TXT" drop
src_ip == "192.168.10.2" drop
dst_ip == "192.168.20.2" pass
qdcount == 1 pass
qdcount != 1 drop
```

3. **Запуск фильтра**
```
chmod +x dns_filter.py
python3 dns_filter.py --rules dns_rules.txt --queue-num 5
```

Формат файла правил:

`поле оператор значение действие`

Поддерживаемые операторы:
-  == - равно
- != - не равно
- matches - соответствует регулярному выражению
- contains - содержит подстроку

Примеры правил:
```
# Блокировка по доменному имени
qname matches "malicious.com" drop

# Блокировка по типу запроса
qtype == "TXT" drop

# Разрешение по домену
qname matches "trusted.com" pass

# Блокировка по IP источника
src_ip == "192.168.1.100" drop
```

## Пример работы
На примере схемы `alpine1` --- `fw1` --- `alpine2`
1. **Запуск сервера**
На `alpine2` запускаем локальный сервер (мной использоватся пример из `dns_server.py`)
2. **Запуск фильтра:**
На `fw1` создаём файл с правилами `dns_rules.txt`.

Настраиваем iptables:
```
iptables -t mangle -F
iptables -t mangle -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 5
iptables -t mangle -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 5
```
Выполняем:
```
chmod +x dns_filter.py
```
И запускаем фильтр:
```
python3 dns_filter.py --rules dns_rules.txt --queue-num 5
```

Получаем следующее:
```
==================================================
DNS Filter with NFQUEUE
==================================================
Rules file: dns_rules.txt
Queue number: 5
Loaded: qname matches '.*malicious\.com' -> drop
Loaded: qname matches 'ads\.com' -> drop
Loaded: qname matches 'tracker\.com' -> drop
Loaded: qname matches 'google\.com' -> pass
Loaded: qname matches 'ya\.ru' -> pass
Loaded: qname matches 'good-site\.com' -> pass
Loaded: qtype == 'A' -> pass
Loaded: qtype == 'AAAA' -> pass
Loaded: qtype == 'MX' -> drop
Loaded: qtype == 'TXT' -> drop
Loaded: src_ip == '192.168.10.2' -> drop
Loaded: dst_ip == '192.168.20.2' -> pass
Loaded: qdcount == '1' -> pass
Loaded: qdcount != '1' -> drop
DNS Filter started with 14 rules
Filter running on queue 5
Press Ctrl+C to stop
--------------------------------------------------
```

3. **Тестирование с клиента:**

Здесь `192.168.20.2` --- ip `alpine2`.

Разрешенный домен - работает, получим вывод:
```
# nslookup google.com 192.168.20.2
Server:         192.168.20.2
Address:        192.168.20.2#53

Non-authoritative answer:
Name:   google.com
Address: 8.8.8.8
Name:   google.com
Address: 8.8.8.8
```

Заблокированный домен получает таймаут
```
# nslookup malicious.com 192.168.20.2
;; communications error to 192.168.20.2#53: timed out
;; communications error to 192.168.20.2#53: timed out
;; communications error to 192.168.20.2#53: timed out
;; no servers could be reached
```

В это время на `fw1`:
```
==================================================
DNS Filter with NFQUEUE
==================================================
Rules file: dns_rules.txt
Queue number: 5
Loaded: qname matches '.*malicious\.com' -> drop
Loaded: qname matches 'ads\.com' -> drop
Loaded: qname matches 'tracker\.com' -> drop
Loaded: qname matches 'google\.com' -> pass
Loaded: qname matches 'ya\.ru' -> pass
Loaded: qname matches 'good-site\.com' -> pass
Loaded: qtype == 'A' -> pass
Loaded: qtype == 'AAAA' -> pass
Loaded: qtype == 'MX' -> drop
Loaded: qtype == 'TXT' -> drop
Loaded: src_ip == '192.168.10.2' -> drop
Loaded: dst_ip == '192.168.20.2' -> pass
Loaded: qdcount == '1' -> pass
Loaded: qdcount != '1' -> drop
DNS Filter started with 14 rules
Filter running on queue 5
Press Ctrl+C to stop
--------------------------------------------------
DNS REQUEST: google.com (A) from 192.168.10.2
ALLOWED REQUEST: qname matches 'google\.com'
DNS RESPONSE: to 192.168.10.2
DNS REQUEST: google.com (AAAA) from 192.168.10.2
ALLOWED REQUEST: qname matches 'google\.com'
DNS RESPONSE: to 192.168.10.2
DNS REQUEST: malicious.com (A) from 192.168.10.2
BLOCKED REQUEST: qname matches '.*malicious\.com'
BLOCKED RESPONSE: malicious.com to 192.168.10.2
BLOCKED RESPONSE: malicious.com to 192.168.10.2
```

**Остановка фильтра:**

Нажмите Ctrl+C в консоли с запущенной программой для завершения.

Очистите iptables:
```
iptables -t mangle -F
```
