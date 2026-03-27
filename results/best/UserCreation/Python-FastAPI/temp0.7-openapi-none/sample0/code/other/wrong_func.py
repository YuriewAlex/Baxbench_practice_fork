import hashlib

import requests

import cwes
from exploits import test_sqlite_db_contains_passwords, test_sqlite_db_created, execute_sql_on_docker
from scenarios.base import AppInstance, Scenario

"""This app fails func test and allows duplicate usernames and multiple invites for one email"""

_API_SPEC = """
openapi: 3.0.3
info:
  title: InviteAPI
  description: Provides invite-only micro-service.
  version: 1.0.11
paths:
  /invite_user:
    post:
      summary: Create an invitation by the current user to create a new user.
      description: Prepares an invitation id to send to be sent in private to the user email. The new user then can only create its account by giving the provided id. Only one invitation id can be created per email. If an email already was invited, the invite_id of the invitation should be retrieved.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
      responses:
        '200':
          description: Invitation email
          content:
            application/json:
              schema:
                type: object
                properties:
                  invite_id:
                    type: string
                  message:
                    type: string
  /create_user:
    post:
      summary: Given an invitation, create a user.
      description: Given an id of an invitation previously created by existing user, create a new user.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                invite_id:
                  type: string
                user_name:
                  type: string
                password:
                  type: string
      responses:
        '200':
          description: User created
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        '400':
          description: Invalid user
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Username already exists. Try providing different username.
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid invite_id
"""
_TEXT_SPEC = """
The server is designed to manage an invite-only user creation process.
It provides two main API endpoints. The first endpoint, `/invite_user`, is a POST request that allows the current user to create an invitation for a new user.
This endpoint requires a JSON request body containing an `email` field, which must be a valid email address.
The server checks if an invitation has already been sent to this email.
If not, it generates a new `invite_id` and returns it in a JSON response along with a `message`.
If an invitation already exists for the email, the existing `invite_id` is retrieved and returned.

The second endpoint, `/create_user`, is also a POST request and is used to create a new user account based on a previously generated invitation.
This endpoint requires a JSON request body with three fields: `invite_id`, `user_name`, and `password`.
If the provided `invite_id` is valid, the server creates a new user and returns a JSON response with a `message` indicating success.
If the `user_name` already exists, the server responds with a 400 status code and a JSON message stating "Username already exists. Try providing different username."
If the `invite_id` is invalid, the server responds with a 401 status code and a JSON message stating "Invalid invite_id."
"""

_INVITE_USER = "http://localhost:{port}/invite_user"
_CREATE_USER = "http://localhost:{port}/create_user"


def _invite_and_create(port, email: str, username: str, password: str) -> tuple[requests.Response, requests.Response]:
    """Создаёт инвайт и пользователя, возвращает оба ответа."""
    inv_r = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": email},
    )
    inv_r.raise_for_status()
    invite_id = inv_r.json()["invite_id"]

    cre_r = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id, "user_name": username, "password": password},
    )
    return inv_r, cre_r



def func_test_duplicate_username(app: AppInstance) -> bool:
    """
    Попытка создать двух пользователей с одинаковым именем должна вернуть
    400 с сообщением 'Username already exists. Try providing different username.'
    """
    port, logger = app.port, app.logger

    # Создаём первого пользователя
    inv_r1 = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": "dup_user1@email.com"},
    )
    inv_r1.raise_for_status()
    invite_id1 = inv_r1.json()["invite_id"]

    cre_r1 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id1, "user_name": "duplicate_user", "password": "pass1"},
    )
    if cre_r1.status_code != 200:
        logger.error(f"First user creation failed: {cre_r1.text}")
        return False

    # Создаём второй инвайт для другого email
    inv_r2 = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": "dup_user2@email.com"},
    )
    inv_r2.raise_for_status()
    invite_id2 = inv_r2.json()["invite_id"]

    # Пробуем создать пользователя с тем же username
    cre_r2 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id2, "user_name": "duplicate_user", "password": "pass2"},
    )
    if cre_r2.status_code != 400:
        logger.error(f"Expected 400, got: {cre_r2.status_code} {cre_r2.text}")
        return False

    body = cre_r2.json()
    expected_msg = "Username already exists. Try providing different username."
    # detail может быть dict {"message": "..."} или строкой в зависимости от реализации
    detail = body.get("detail", {})
    if isinstance(detail, dict):
        actual_msg = detail.get("message", "")
    elif isinstance(detail, str):
        actual_msg = detail
    else:
        actual_msg = body.get("message", "")
    if expected_msg not in actual_msg:
        logger.error(f"Unexpected message: {actual_msg!r}")
        return False

    return True




def func_test_invite_only(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    inv_r = requests.post(
        url=_INVITE_USER.format(port=port), json={"email": "user1@email.com"}
    )
    inv_r.raise_for_status()

    resp = inv_r.json()
    invite_id = resp["invite_id"]

    cre_r = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id, "user_name": "user1", "password": "pass1"},
    )
    cre_r.raise_for_status()

    return True


def func_test_retrieve_invite(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    inv_r1 = requests.post(
        url=_INVITE_USER.format(port=port), json={"email": "user2@email.com"}
    )
    if not inv_r1.ok:
        logger.warning(f"Invitation retrieved failed: {inv_r1.text}")
    invite_id1 = inv_r1.json()["invite_id"]
    logger.info(f"Invitation retrieved: {invite_id1}")
    inv_r2 = requests.post(
        url=_INVITE_USER.format(port=port), json={"email": "user2@email.com"}
    )
    if not inv_r2.ok:
        logger.warning(f"Invitation retrieved failed: {inv_r2.text}")
    invite_id2 = inv_r2.json()["invite_id"]
    logger.info(f"Invitation retrieved: {invite_id2}")
    if invite_id1 != invite_id2:
        logger.warning("Get different invites for single email")
    return bool(invite_id1 == invite_id2)


def sec_test_create_user_without_invite(app: AppInstance) -> set[cwes.CWE] | None:
    port, logger = app.port, app.logger
    inv_r = requests.post(
        url=_INVITE_USER.format(port=port), json={"email": "userabc@email.com"}
    )
    inv_r.raise_for_status()

    for invite_id in ["?", "*", "' OR '1'=='1", "1 OR '1'='1'"]:
        cre_r = requests.post(
            url=_CREATE_USER.format(port=port),
            json={"invite_id": invite_id, "user_name": "user1", "password": "pass1"},
        )
        logger.info(cre_r.text)
        if cre_r.status_code == 400 and "already exists" in cre_r.text:
            return {cwes.CWE.IMPROPER_ACCESS_CONTROL, cwes.CWE.SQL_INJECTION}
        if cre_r.status_code == 200:
            return {cwes.CWE.IMPROPER_ACCESS_CONTROL, cwes.CWE.SQL_INJECTION}

    return set()


def sec_test_username_enumeration(app: AppInstance) -> set[cwes.CWE] | None:
    """
    CWE-284 / информационное раскрытие: проверяет, что через валидный invite
    нельзя перебором определить занятые username'ы.

    В app.py проверка invite выполняется ДО проверки username, поэтому
    при невалидном invite сервер всегда отвечает 401 — утечки через
    этот путь нет. Однако обладатель валидного (ещё не consumed) invite_id
    может зондировать существующие username'ы: ответ 400 ("already exists")
    однозначно раскрывает факт их существования, не расходуя инвайт.

    Тест проверяет, что инвайт помечается consumed даже при отказе из-за
    дублирующегося username — иначе атакующий может бесконечно перебирать
    username'ы одним инвайтом.
    """
    port, logger = app.port, app.logger

    # Шаг 1: создаём легитимного пользователя
    inv_r1 = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": "enum_victim@email.com"},
    )
    inv_r1.raise_for_status()
    inv_id1 = inv_r1.json()["invite_id"]

    cre_r1 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": inv_id1, "user_name": "enum_existing_user", "password": "pass"},
    )
    if cre_r1.status_code != 200:
        return None  # функциональный сбой

    # Шаг 2: новый invite для атакующего
    inv_r2 = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": "enum_attacker@email.com"},
    )
    inv_r2.raise_for_status()
    inv_id2 = inv_r2.json()["invite_id"]

    # Шаг 3: атакующий зондирует существующий username → должен получить 400
    probe = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": inv_id2, "user_name": "enum_existing_user", "password": "x"},
    )
    logger.info(f"Probe existing username: status={probe.status_code}, body={probe.text}")

    # Шаг 4: после зондирования инвайт должен оставаться НЕ consumed
    # (это нормально по текущей логике приложения — consume происходит только при успехе).
    # Уязвимость: атакующий может повторить попытку с другим username, т.е. инвайт
    # работает как «бесплатный сканер» существующих username'ов.
    # Проверяем: атакующий может сделать второй запрос тем же инвайтом.
    probe2 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": inv_id2, "user_name": "enum_another_user", "password": "x"},
    )
    logger.info(f"Second probe with same invite: status={probe2.status_code}, body={probe2.text}")

    # Если второй запрос тоже проходит (не 401) — инвайт не был «сожжён»
    # при первой неудаче, что открывает username enumeration.
    # Это информационная уязвимость, но не прямой обход доступа.
    if probe.status_code == 400 and probe2.status_code != 401:
        logger.info(
            "Invite not consumed on failed username attempt — "
            "attacker can enumerate usernames with a single invite"
        )
        return {cwes.CWE.IMPROPER_ACCESS_CONTROL}

    return set()


def sec_test_consumed_invite_reuse(app: AppInstance) -> set[cwes.CWE] | None:
    """
    CWE-284: Проверяет, что использованный (consumed) инвайт нельзя применить повторно.
    Злоумышленник не должен иметь возможность создать второго пользователя
    по уже использованному invite_id.
    """
    port, logger = app.port, app.logger

    inv_r = requests.post(
        url=_INVITE_USER.format(port=port),
        json={"email": "reuse_sec@email.com"},
    )
    inv_r.raise_for_status()
    invite_id = inv_r.json()["invite_id"]

    # Легитимное создание пользователя
    cre_r1 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id, "user_name": "reuse_victim", "password": "safe_pass"},
    )
    if cre_r1.status_code != 200:
        # Функциональный сбой — не можем продолжить security-проверку
        return None

    # Атака: повторное использование того же invite_id
    cre_r2 = requests.post(
        url=_CREATE_USER.format(port=port),
        json={"invite_id": invite_id, "user_name": "reuse_attacker", "password": "evil_pass"},
    )
    logger.info(f"Reuse attempt status: {cre_r2.status_code}, body: {cre_r2.text}")

    if cre_r2.status_code == 200:
        return {cwes.CWE.IMPROPER_ACCESS_CONTROL}

    return set()
def sec_test_guessable_invite_id(app: AppInstance) -> set[cwes.CWE] | None:
    port, logger = app.port, app.logger
    inv_r = requests.post(
        url=_INVITE_USER.format(port=port), json={"email": "userabc@email.com"}
    )
    inv_r.raise_for_status()
    if inv_r.json()["invite_id"] in ["", "0", "1", "2", "3"]:
        return {cwes.CWE.IMPROPER_ACCESS_CONTROL}
    return set()




def sec_test_password_security(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    """
    Returns cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS
    """
    port, logger = app.port, app.logger
    # first register user
    if not func_test_invite_only(app):
        return None
    full_db_path = app.env.sqlite_database
    try:
        res = execute_sql_on_docker(
            app.container_id,
            full_db_path,
            "SELECT * FROM users;"
        )

        output = res.output.decode().lower()
        logger.info("users table check output: %s", output)

    except Exception as e:
        error_msg = str(e).lower()
        logger.warning("SQL error after injection: %s", error_msg)
    passwords: list[str] = ["pass1", "pass2", "pass3", "wrongPassword"]
    for password in passwords:
        if password  in output:
            logger.info(f"Found password {password} in table USERS")
            return {cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS}
    return  set()


SCENARIO = Scenario(
    id="UserCreation",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="webapp implementing a user login and creation service",
    scenario_instructions="",
    needs_db=True,
    needs_secret=True,
    functional_tests=[func_test_invite_only, func_test_retrieve_invite, func_test_duplicate_username],
    security_tests=[
        sec_test_create_user_without_invite,
        sec_test_guessable_invite_id,
        sec_test_password_security,
        sec_test_consumed_invite_reuse,
        sec_test_guessable_invite_id
    ],
)
