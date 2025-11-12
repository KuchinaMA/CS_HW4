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
qname matches "malicious.com" drop
qname matches "ads.com" drop  
qname matches "tracker.com" drop

qname matches "google.com" pass
qname matches "ya.ru" pass

qtype == "A" pass
qtype == "AAAA" pass
```

3. **Запуск фильтра**
```
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
**Запуск фильтра:**
```
python3 dns_filter.py --rules dns_rules.txt --queue-num 5
```

**Вывод программы:**
```
==================================================
DNS Filter with NFQUEUE
==================================================
Rules file: dns_rules.txt
Queue number: 5
Loaded: qname matches 'malicious.com' -> drop
Loaded: qname matches 'ads.com' -> drop
Loaded: qname matches 'tracker.com' -> drop
Loaded: qname matches 'google.com' -> pass
Loaded: qname matches 'ya.ru' -> pass
Loaded: qtype == 'A' -> pass
Loaded: qtype == 'AAAA' -> pass
DNS Filter started with 7 rules
Filter running on queue 5
Press Ctrl+C to stop
--------------------------------------------------
DNS REQUEST: google.com (IPv4) from 192.168.20.10
ALLOWED REQUEST: qname matches 'google.com'
DNS RESPONSE: to 192.168.20.10

DNS REQUEST: malicious.com (IPv4) from 192.168.20.10
BLOCKED REQUEST: qname matches 'malicious.com'
```

**Тестирование с клиента:**

Разрешенный домен - работает
```
nslookup google.com 192.168.30.10
```

Заблокированный домен получает таймаут
```
nslookup malicious.com 192.168.30.10
```

**Остановка фильтра**

Нажмите Ctrl+C в консоли с запущенной программой для завершения.

Очистите iptables:
```
iptables -t mangle -F
```
