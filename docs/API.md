### Использование API

#### Начало работы с docker

1. Запустите docker image docker-compose up, перейдите в UI http://localhost:9191, по адресу http://localhost:9191/swagger это спецификация swagger API
2. Зарегистрируйте пользователя, например, имя пользователя: admin и пароль: admin
3. Войдите в пользовательский интерфейс, в настройках включите разрешить создание домена для пользователей, теперь вы можете создавать домены и управлять ими с учетной записью администратора, а также обычными пользователями
4. Перейдите в меню ключей API, затем нажмите кнопку "Создать ключ", чтобы добавить новый ключ администратора
5. Храните apikey в кодировке base64 в надежном месте, так как он больше не будет доступен


#### Доступ к API

У PDA есть свой собственный API, который не следует путать с PowerDNS API. Имейте в виду, что вам необходимо включить PowerDNS API с помощью ключа, который будет использоваться PDA для управления им. Следовательно, вам следует использовать ключи, созданные PDA, для просмотра API PDA, адреса и порта PDA. Они не предоставляют доступ к API PowerDNS.

API PDA состоит из двух отдельных частей:

- Конечные точки /powerdnsadmin управляют содержимым PDA (учетными записями, пользователями, apikeys), а также разрешают создание/удаление домена
- Конечные точки /server передают запросы через прокси к API серверного экземпляра PowerDNS. PDA действует как прокси, управляющий несколькими ключами API и разрешениями на содержимое PowerDNS.

Запросам к API требуется два заголовка:

- Классический "Content-Type: application/json" требуется для всех запросов POST и PUT, хотя его безопасно использовать при каждом вызове
- Заголовок аутентификации для обеспечения либо базовой аутентификации по логину:паролю, либо аутентификации по ключу Api.

Когда вы получаете доступ к конечной точке `/powerdnsadmin`, вы должны использовать базовую аутентификацию:

```bash
# Encode your user and password to base64
$ echo -n 'admin:admin'|base64
YWRtaW46YWRtaW4=
# Use the ouput as your basic auth header
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' -X <method> <url>
```

Когда вы получаете доступ к конечной точке "/server", вы должны использовать ключ Api

```bash
# Use the already base64 encoded key in your header
curl -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' -X <method> <url>
```

`/sync_domains` принимает как базовую аутентификацию, так и аутентификацию с помощью apikey

#### Examples

Создание зоны через `/powerdnsadmin`:

```bash
curl -L -vvv -H 'Content-Type: application/json' -H 'Authorization: Basic YWRtaW46YWRtaW4=' -X POST http://localhost:9191/api/v1/pdnsadmin/zones --data '{"name": "yourdomain.com.", "kind": "NATIVE", "nameservers": ["ns1.mydomain.com."]}'
```

Создание api-ключа с ролью администратора:

```bash
# Create the key
curl -L -vvv -H 'Content-Type: application/json' -H 'Authorization: Basic YWRtaW46YWRtaW4=' -X POST http://localhost:9191/api/v1/pdnsadmin/apikeys --data '{"description": "masterkey","domains":[], "role": "Administrator"}'
```
Пример ответа (не забудьте сохранить обычный ключ из выходных данных)

```json
[
  {
    "accounts": [],
    "description": "masterkey",
    "domains": [],
    "role": {
      "name": "Administrator",
      "id": 1
    },
    "id": 2,
    "plain_key": "aGCthP3KLAeyjZI"
  }
]
```

Мы можем использовать ключ api для всех вызовов PowerDNS (не забудьте указать Content-Type):

Получение конфигурации powerdns (необходим ключ администратора):

```bash
curl -L -vvv -H 'Content-Type: application/json' -H 'X-API-KEY: YUdDdGhQM0tMQWV5alpJ' -X GET http://localhost:9191/api/v1/servers/localhost/config
```

Создание и обновление записей:

```bash
curl -X PATCH -H 'Content-Type: application/json' --data '{"rrsets": [{"name": "test1.yourdomain.com.","type": "A","ttl": 86400,"changetype": "REPLACE","records": [ {"content": "192.0.2.5", "disabled": false} ]},{"name": "test2.yourdomain.com.","type": "AAAA","ttl": 86400,"changetype": "REPLACE","records": [ {"content": "2001:db8::6", "disabled": false} ]}]}' -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' http://127.0.0.1:9191/api/v1/servers/localhost/zones/yourdomain.com.
```

Получить информацию о домене:

```bash
curl -L -vvv -H 'Content-Type: application/json' -H 'X-API-KEY: YUdDdGhQM0tMQWV5alpJ' -X GET http://localhost:9191/api/v1/servers/localhost/zones/yourdomain.com
```

Получить записи зоны:

```bash
curl -H 'Content-Type: application/json' -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' http://localhost:9191/api/v1/servers/localhost/zones/yourdomain.com
```

Добавить новую запись:

```bash
curl -H 'Content-Type: application/json' -X PATCH --data '{"rrsets": [ {"name": "test.yourdomain.com.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "192.0.5.4", "disabled": false } ] } ] }' -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' http://localhost:9191/api/v1/servers/localhost/zones/yourdomain.com | jq .
```

Обновить запись:

```bash
curl -H 'Content-Type: application/json' -X PATCH --data '{"rrsets": [ {"name": "test.yourdomain.com.", "type": "A", "ttl": 86400, "changetype": "REPLACE", "records": [ {"content": "192.0.2.5", "disabled": false, "name": "test.yourdomain.com.", "ttl": 86400, "type": "A"}]}]}' -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' http://localhost:9191/api/v1/servers/localhost/zones/yourdomain.com | jq .
```

Удалить запись:

```bash
curl -H 'Content-Type: application/json' -X PATCH --data '{"rrsets": [ {"name": "test.yourdomain.com.", "type": "A", "ttl": 86400, "changetype": "DELETE"}]}' -H 'X-API-Key: YUdDdGhQM0tMQWV5alpJ' http://localhost:9191/api/v1/servers/localhost/zones/yourdomain.com | jq
```

### Генерация диаграммы ER

С помощью докера

```bash
# Установка пакетов сборки
apt-get install python-dev graphviz libgraphviz-dev pkg-config
# Получите необходимые библиотеки python
pip install graphviz mysqlclient ERAlchemy
# Запустите контейнер docker
docker-compose up -d
# Установите переменные окружения
source .env
# Сгенерируйте диаграммы
eralchemy -i 'mysql://${PDA_DB_USER}:${PDA_DB_PASSWORD}@'$(docker inspect powerdns-admin-mysql|jq -jr '.[0].NetworkSettings.Networks.powerdnsadmin_default.IPAddress')':3306/powerdns_admin' -o /tmp/output.pdf
```
