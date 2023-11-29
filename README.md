# PowerDNS-Admin

Веб-интерфейс PowerDNS с расширенными функциями

#### Функции:

- Обеспечивает прямое и обратное управление зонами
- Предоставляет функции создания шаблонов зон
- Обеспечивает управление пользователями с контролем доступа на основе ролей
- Обеспечивает контроль доступа для конкретной зоны
- Обеспечивает ведение журнала действий
- Аутентификация:
   - Поддержка локальных пользователей
   - Поддержка SAML
   - Поддержка LDAP: OpenLDAP / Active Directory
   - Поддержка OAuth: Google / GitHub / Azure / OpenID
   - Поддержка двухфакторной аутентификации (TOTP)
- Настройка службы DNS и мониторинг статистики
- Поддержка протокола DynDNS 2
- Простое редактирование записи IPv6 PTR
- Предоставляет API для управления зонами и записями среди других функций
- Обеспечивает полную поддержку IDN/Punycode

## Запуск PowerDNS-Admin

There are several ways to run PowerDNS-Admin. The quickest way is to use Docker.
If you are looking to install and run PowerDNS-Admin directly onto your system, check out
the [wiki](https://github.com/PowerDNS-Admin/PowerDNS-Admin/blob/master/docs/wiki/) for ways to do that.

#### Установка: используя docker-compose

1. Обновите конфигурацию   
   * Отредактируйте файл `docker-compose.yml`, чтобы обновить строку подключения к базе данных в `SQLALCHEMY_DATABASE_URL`.
   Другие переменные среды упоминаются в [legal_env vars](configs/docker_config.py).
   * Чтобы использовать функцию Docker secrets, можно добавить `_FILE` к переменным среды и указать на файл с сохраненными в нем значениями.   
   * Обязательно установите для переменной окружения `SECRET_KEY` значение long random строка (https://flask.palletsprojects.com/en/1.1.x/config/#SECRET_KEY)

2. Запустите контейнер docker
   ```
   $ docker-compose
   ```

Затем вы можете получить доступ к PowerDNSAdmin, указав в своем браузере на http://localhost:9191