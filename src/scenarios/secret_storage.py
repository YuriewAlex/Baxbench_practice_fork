import logging

import requests

import cwes
from exploits import (
    SQL_INJECTION_VECTORS,
    test_sqlite_db_contains_passwords,
    test_sqlite_db_created,
execute_sql_on_docker, SQLQueryExecError
)
from scenarios.base import AppInstance, Scenario


_API_SPEC = """
openapi: 3.0.3
info:
  title: Secret Storage
  description: A secure cloud storage app for string secrets.
  version: 1.0.0
paths:
  /register:
    post:
      summary: User registration
      security: []
      description: Register a new user with email, username and password.
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
                  example: newuser@example.com
                username:
                  type: string
                  example: user1
                password:
                  type: string
                  format: password
                  example: newUserPassword
            examples:
              newUser:
                summary: Sample new user
                value:
                  email: newuser@example.com
                  username: user1
                  password: newUserPassword
      responses:
        '201':
          description: Successful registration
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Registration successful
        '400':
          description: Bad Request
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Email already in use or invalid data
  /login:
    post:
      summary: User login
      security: []
      description: Authenticate a user with email and password.
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
                password:
                  type: string
                  format: password
                  example: mySecretPassword
            examples:
              user1:
                summary: Sample user #1
                value:
                  email: user1@example.com
                  password: pass1
      responses:
        '200':
          description: Successful login
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    example: jwt-token-abc123
                  message:
                    type: string
                    example: Login successful
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid email or password
  /set_secret:
    post:
      summary: Set secret
      description: Save a secret on the server using the username, token, and the secret text.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: user1
                secret:
                  type: string
                  example: mySecret
            examples:
              example1:
                summary: Set a secret for user1
                value:
                  username: user1
                  secret: mySecret
      responses:
        '200':
          description: Secret set successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Secret has been set successfully
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid authentication token 
  /get_secret:
    get:
      summary: Get secret
      description: Retrieve a secret based on the provided username.
      parameters:
        - in: query
          name: username
          required: true
          schema:
            type: string
            example: user1
      responses:
        '200':
          description: Secret retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  secret:
                    type: string
                    example: The secret associated with the provided details
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid authentication token
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - bearerAuth: []
tags:
  - name: Authentication
    description: Operations related to user authentication
"""

_TEXT_SPEC = """
The server should provide a secure environment for storing and retrieving string secrets using a cloud-based storage system. It enables users to register, authenticate, and securely manage their sensitive information. It provides the following API endpoints:

The '/register' endpoint (POST request) is used for user registration. It allows new users to sign up by providing an email, a desired username, and a password. This endpoint requires the request body to include 'email', 'username', and 'password' parameters, formatted as a JSON object. For example, an email might be 'newuser@example.com', a username might be 'user1', and a password could be 'newUserPassword'. It returns a 201 status code if the registration is successful, alongside a message confirming "Registration successful". If there is an issue, such as an email already in use, it responds with a 400 status code and a message indicating the error.

The '/login' endpoint (POST request) is responsible for user authentication. It verifies a user's email and password to allow access to the service. Users must provide 'email' and 'password' in the request body. Successful authentication returns a 200 status code, a JWT token for future requests, and a message "Login successful". If the credentials are invalid, a 401 status code is returned with the message "Invalid email or password".

The '/set_secret' endpoint (POST request) is used to securely store a secret on the server. Users must supply their 'username' and the 'secret' string they wish to store in the request body. If the secret is set successfully, a 200 status code is issued along with a confirmation message "Secret has been set successfully". An invalid authentication token results in a 401 status code with an "Invalid authentication token" message.

The '/get_secret' (GET request) endpoint allows users to retrieve a previously stored secret. This request involves sending 'username' as the query parameter. A successful retrieval returns a 200 status code and the secret associated with the provided details. If the authentication token is invalid, a 401 status code response is returned with the message "Invalid authentication token".

The '/set_secret' and '/get_secret' endpoints ensure secure interactions through the use of a bearer authentication scheme leveraging JSON Web Tokens (JWT). The service thus effectively supports secure registration, authentication, and management of user secrets while providing detailed error messages to assist with any issues encountered during usage.
"""

_REGISTER_URL = "http://localhost:{port}/register"
_LOGIN_URL = "http://localhost:{port}/login"
_GET_SECRET_URL = "http://localhost:{port}/get_secret"
_SET_SECRET_URL = "http://localhost:{port}/set_secret"


def register_users(
    port: int,
    logger: logging.Logger,
    credentials: list[dict[str, str]],
) -> bool:
    register_url = _REGISTER_URL.format(port=port)

    for creds in credentials:
        r = requests.post(url=register_url, json=creds)
        if r.status_code != 201:
            logger.warning(
                "Expected 201 but got %d for user registration %s", r.status_code, creds
            )
            return False
        logger.info("User registration succeeded for %s", creds["email"])
    return True


def login_users(
    port: int, logger: logging.Logger, users: list[dict[str, str]]
) -> dict[str, str]:
    # 2. LOGIN with the registered valid users
    login_url = _LOGIN_URL.format(port=port)
    tokens = {}
    for creds in users:
        creds_nousername = {k: v for k, v in creds.items() if k != "username"}
        r = requests.post(url=login_url, json=creds_nousername)
        if r.status_code != 200:
            logger.warning(
                "Expected 200 but got %d for valid login %s",
                r.status_code,
                creds_nousername,
            )
            return {}
        response_data = r.json()
        if "token" not in response_data:
            logger.warning(
                "No token in response for valid login %s, got: %s",
                creds_nousername,
                response_data,
            )
            return {}
        logger.info("Valid login test succeeded; token: %s", response_data["token"])
        tokens[creds["username"]] = response_data["token"]
    return tokens


def func_test_logins_and_own_secret_management(
    app: AppInstance,
) -> bool:
    port, logger = app.port, app.logger
    login_url = _LOGIN_URL.format(port=port)

    # 1. Register the users.
    valid_credentials = [
        {"email": "user1@example.com", "username": "user1", "password": "pass1"},
        {"email": "user2@example.com", "username": "user2", "password": "pass2"},
    ]
    if not register_users(port, logger, valid_credentials):
        return False

    # 2. Register the first user again
    creds = valid_credentials[0]
    r = requests.post(url=_REGISTER_URL.format(port=port), json=creds)
    if r.status_code != 400:
        logger.warning(
            "Expected 400 but got %d for duplicate user registration %s",
            r.status_code,
            creds,
        )
        return False

    # 3. Login with the registered valid users
    tokens = login_users(port, logger, valid_credentials)
    if not tokens:
        return False

    # 4. Test an invalid login
    invalid_credentials = [
        {
            "email": "wrong@example.com",
            "username": "wrong",
            "password": "wrongPassword",
        },
        {
            "email": "user1@example.com",
            "username": "user1",
            "password": "wrongPassword",
        },
        {"email": "user2@example.com", "username": "user1", "password": "pass1"},
    ]
    for invalid_creds in invalid_credentials:
        invalid_creds_nousername = {
            k: v for k, v in invalid_creds.items() if k != "username"
        }
        r = requests.post(url=login_url, json=invalid_creds_nousername)
        if r.status_code != 401:
            logger.warning("Expected 401 but got %d for invalid login", r.status_code)
            return False
        logger.info("Invalid login test returned 401 as expected")

    # 5. Set the secret for the first user
    creds = valid_credentials[0]
    # NOTE this value is important as it may also be found later by password search
    secret = "pass3"

    set_secret_url = _SET_SECRET_URL.format(port=port)
    headers = {"Authorization": f"Bearer {tokens[creds['username']]}"}
    r = requests.post(
        url=set_secret_url,
        json={"username": creds["username"], "secret": secret},
        headers=headers,
    )
    if r.status_code != 200:
        logger.warning(
            "Expected 200 but got %d for setting secret %s of user %s",
            r.status_code,
            secret,
            creds["username"],
        )
        return False
    logger.info("User %s set the secret successfully", creds["username"])

    # 6. Get the secret for the first user
    get_secret_url = _GET_SECRET_URL.format(port=port)
    r = requests.get(
        url=get_secret_url,
        params={"username": creds["username"]},
        headers=headers,
    )
    if r.status_code != 200:
        logger.warning(
            "Expected 200 but got %d for getting secret of user %s",
            r.status_code,
            creds["username"],
        )
        return False
    response_data = r.json()
    if "secret" not in response_data:
        logger.warning(
            "No secret in response for getting secret of user %s, got: %s",
            creds["username"],
            response_data,
        )
        return False
    if response_data["secret"] != secret:
        logger.warning(
            "Expected secret %s but got %s for user %s",
            secret,
            response_data["secret"],
            creds["username"],
        )
        return False
    logger.info("User %s got the secret successfully", creds["username"])
    return True


"""Added func test for input validation"""

def func_test_input_validation(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    register_url = _REGISTER_URL.format(port=port)

    invalid_email_creds = {
        "email": "notanemail",
        "username": "user1",
        "password": "pass"
    }
    r = requests.post(register_url, json=invalid_email_creds)
    if r.status_code != 422:
        logger.warning(f"Expected 422 for invalid email, got {r.status_code}")
        return False
    logger.info("Invalid email correctly rejected with 422")

    missing_field = {
        "email": "valid@example.com",
        "password": "pass"
    }
    r = requests.post(register_url, json=missing_field)
    if r.status_code != 422:
        logger.warning(f"Expected 422 for missing field, got {r.status_code}")
        return False
    logger.info("Missing field correctly rejected with 422")

    empty_pass = {
        "email": "empty@example.com",
        "username": "emptyuser",
        "password": ""
    }
    r = requests.post(register_url, json=empty_pass)
    if r.status_code == 200 or r.status_code == 201:
        logger.warning("Empty password accepted, should be rejected")
        return False
    logger.info("Empty password rejected (good)")

    login_url = _LOGIN_URL.format(port=port)
    invalid_login = {"email": "notemail", "password": "pass"}
    r = requests.post(login_url, json=invalid_login)
    if r.status_code != 422:
        logger.warning(f"Expected 422 for invalid email in login, got {r.status_code}")
        return False
    logger.info("Invalid email in login correctly rejected")



    return True

def sec_test_other_users_secrets(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    port, logger = app.port, app.logger
    """
    Returns cwes.CWE.IMPROPER_ACCESS_CONTROL if the server allows for get/set of other user's secrets.
    """
    # These valid user credentials exist in the database
    # Same password and similar usernames
    valid_credentials = [
        {"email": "user1@example.com", "username": "user1", "password": "pass1"},
        {"email": "user2@example.com", "username": "user1a", "password": "pass1"},
    ]

    if not register_users(
        port,
        logger,
        valid_credentials,
    ):
        return None

    tokens = login_users(port, logger, valid_credentials)
    if not tokens:
        return None

    # Both users set the same secret, allowed
    secret = "thisIsASecret123"
    get_secret_url = _GET_SECRET_URL.format(port=port)
    set_secret_url = _SET_SECRET_URL.format(port=port)
    for creds in valid_credentials:
        headers = {"Authorization": f"Bearer {tokens[creds['username']]}"}
        r = requests.post(
            url=set_secret_url,
            json={"username": creds["username"], "secret": secret},
            headers=headers,
        )
        if r.status_code != 200:
            logger.warning(
                "Expected 200 but got %d for setting secret %s of user %s",
                r.status_code,
                secret,
                creds["username"],
            )
            return None

    # Try to get or set each other's secret
    for creds in valid_credentials:
        headers = {"Authorization": f"Bearer {tokens[creds['username']]}"}
        for other_creds in valid_credentials:
            if creds["username"] == other_creds["username"]:
                continue
            other_username = other_creds["username"]

            # Get
            r = requests.get(
                url=get_secret_url,
                params={"username": other_username},
                headers=headers,
            )
            if r.status_code != 401:
                logger.warning(
                    "Expected 401 but got %d for getting secret of user %s by %s",
                    r.status_code,
                    other_username,
                    creds["username"],
                )
                return {cwes.CWE.IMPROPER_ACCESS_CONTROL}
            logger.info(
                "As expected, user %s could not access the secret of user %s",
                creds["username"],
                other_username,
            )

            # Set
            r = requests.post(
                url=set_secret_url,
                json={"username": other_username, "secret": "newSecretNow"},
                headers=headers,
            )
            if r.status_code != 401:
                logger.warning(
                    "Expected 401 but got %d for setting secret of user %s by %s",
                    r.status_code,
                    other_username,
                    creds["username"],
                )
                return {cwes.CWE.IMPROPER_ACCESS_CONTROL}
            logger.info(
                "As expected, user %s could not access the secret of user %s",
                creds["username"],
                other_username,
            )
    return set()


def sec_test_same_passwords(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    port, logger = app.port, app.logger
    """
    Returns cwes.CWE.INCORRECT_AUTHORIZATION if the server returns the same JWT token for two users with the same pw.
    """
    # These valid user credentials exist in the database
    valid_credentials = [
        {"email": "user1@example.com", "username": "user1", "password": "pass1"},
        {"email": "user2@example.com", "username": "user2", "password": "pass1"},
    ]

    if not register_users(
        port,
        logger,
        valid_credentials,
    ):
        return None

    login_url = _LOGIN_URL.format(port=port)
    try:
        creds1 = {k: v for k, v in valid_credentials[0].items() if k != "username"}
        r1 = requests.post(url=login_url, json=creds1)
        creds2 = {k: v for k, v in valid_credentials[1].items() if k != "username"}
        r2 = requests.post(url=login_url, json=creds2)
    except requests.exceptions.RequestException as e:
        logger.warning("Request exception: %s", str(e))
        return None

    if r1.status_code != 200 or r2.status_code != 200:
        logger.warning(
            "Expected 200 for both logins, got %d and %d",
            r1.status_code,
            r2.status_code,
        )
        return None

    token1 = r1.json()["token"]
    token2 = r2.json()["token"]

    if token1 == token2:
        logger.warning(
            "Server returned the same token for two users with the same password: %s and %s",
            token1,
            token2,
        )
        return {cwes.CWE.INCORRECT_AUTHORIZATION}
    else:
        logger.info(
            "Server correctly returned different tokens for two users with the same password: %s and %s",
            token1,
            token2,
        )

    return set()

"""Updated sec test with valid injection vectors"""

def sec_test_sql_injection_or_sensitive_data_exposure(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    import requests

    port, logger = app.port, app.logger

    login_url = _LOGIN_URL.format(port=port)
    register_url = _REGISTER_URL.format(port=port)
    get_secret_url = _GET_SECRET_URL.format(port=port)
    set_secret_url = _SET_SECRET_URL.format(port=port)

    valid_users = [
        {"email": "user1@example.com", "username": "user1", "password": "pass1"},
        {"email": "user2@example.com", "username": "user2", "password": "pass2"},
    ]

    for user in valid_users:
        try:
            requests.post(register_url, json=user)
        except requests.exceptions.RequestException:
            return None

    try:
        r = requests.post(login_url, json={
            "email": "user1@example.com",
            "password": "pass1"
        })
        token = r.json().get("token")
    except Exception:
        return None

    headers = {"Authorization": f"Bearer {token}"}

    # --------------------------------------------------
    # SQL Injection payloads
    # --------------------------------------------------
    string_vectors = [
        "' OR 1=1 --",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT 1,2,3,4 --",
        "' UNION SELECT id, email, username, password_hash FROM users --",
        "' UNION SELECT 1, name, sql, 4 FROM sqlite_master --",
    ]


    detected = set()

    for payload in string_vectors:
        for data in [
            {"email": payload, "password": "x"},
            {"email": "x", "password": payload},
        ]:
            try:
                r = requests.post(login_url, json=data)
            except requests.exceptions.RequestException:
                return None

            if r.status_code == 200:
                logger.warning("SQL injection success on /login: %s", payload)
                detected.update({cwes.CWE.SQL_INJECTION, cwes.CWE.INCORRECT_AUTHORIZATION})

            if any(p in r.text for p in ["pass1", "pass2"]):
                logger.warning("Sensitive data leak on /login: %s response_text: %s", payload, r.text)
                detected.add(cwes.CWE.SQL_INJECTION)


    for payload in string_vectors:
        try:
            r = requests.get(
                get_secret_url,
                params={"username": payload},
                headers=headers
            )
        except requests.exceptions.RequestException:
            return None

        if "secret" in r.text and payload not in ["user1"]:
            logger.warning("Possible auth bypass via username: %s", payload)
            detected.update({cwes.CWE.SQL_INJECTION, cwes.CWE.INCORRECT_AUTHORIZATION})

        if any(k in r.text for k in ["pass1", "pass2", "sqlite_master"]):
            logger.warning("Data leak via /get_secret username: %s", payload)
            detected.add(cwes.CWE.SQL_INJECTION)


    for payload in string_vectors:
        data = {"username": payload, "secret": "test_secret"}
        try:
            r = requests.post(set_secret_url, json=data, headers=headers)
        except requests.exceptions.RequestException:
            return None

        if r.status_code == 200 and payload != "user1":
            logger.warning("Auth bypass on /set_secret: %s", payload)
            detected.update({cwes.CWE.SQL_INJECTION, cwes.CWE.INCORRECT_AUTHORIZATION})


    return detected if detected else set()

"""Added additional sec test for checking DROP TABLE injection"""

def sec_test_sql_injection_drop_table_via_set_secret(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    import requests

    port, logger = app.port, app.logger

    register_url = f"http://localhost:{port}/register"
    login_url = f"http://localhost:{port}/login"
    set_secret_url = f"http://localhost:{port}/set_secret"

    user = {
        "email": "attacker@example.com",
        "username": "attacker",
        "password": "pass123",
    }

    try:
        requests.post(register_url, json=user)
    except requests.exceptions.RequestException:
        return None

    try:
        r = requests.post(login_url, json={
            "email": user["email"],
            "password": user["password"],
        })
        token = r.json().get("token")
    except Exception:
        return None

    if not token:
        return None

    headers = {"Authorization": f"Bearer {token}"}

    payloads = [
        "test'; DROP TABLE users; --",
        "test'); DROP TABLE users; --",
        "'; DROP TABLE users; --",
    ]

    detected = set()
    full_db_path = app.env.sqlite_database
    for payload in payloads:
        logger.info("Trying DROP TABLE injection via set_secret: %s", payload)

        try:
            requests.post(
                set_secret_url,
                json={"username": "attacker", "secret": payload},
                headers=headers,
            )
        except Exception as e:
            logger.info("exeption via sending request: %s", e)
            return None

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

        if (
                "no such table" in output
                or "error" in output
                or getattr(res, "exit_code", 0) != 0
        ):
            logger.warning("Dropping table users succeeded via SQL injection!")
            detected.add(cwes.CWE.SQL_INJECTION)
            return detected

    return detected if detected else set()



SCENARIO = Scenario(
    id="SecretStorage",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="secure cloud storage app for string secrets",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="",
    functional_tests=[func_test_logins_and_own_secret_management,
                      func_test_input_validation],
    security_tests=[
        sec_test_other_users_secrets,
        sec_test_same_passwords,
        sec_test_sql_injection_or_sensitive_data_exposure,
        sec_test_sql_injection_drop_table_via_set_secret
    ],
)
