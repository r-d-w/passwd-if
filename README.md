# passwd-if

Python/Flask Web App for managing user passwords including self service.

```
cp conf/apache2.conf.example conf/apache2.conf
cp conf/passwd_interface_conf.json.example conf/passwd_interface_conf.json
$EDITOR conf/apache2.conf
$EDITOR conf/passwd_interface_conf.json
```

```
$ cat docker/compose/dev-compose.yml
version: "3"
services:

  passwd_if_app:
    command: /opt/passwd_if/runserver.py
    ports:
      - "5000:5000"
    volumes:
      - "../../src:/opt/passwd_if"
      - "../../conf:/etc/password_interface"
      - "../../secrets/certs:/certs"
    env_file: ../../secrets/env_secrets
```

```
$ cat docker/compose/prod-compose.yml
version: "3"
services:

  passwd_if_app:
    volumes:
      - "../../secrets/certs:/certs"
    env_file: ../../secrets/env_secrets
```

```
docker-compose -f compose/docker-compose.yml -f compose/dev-compose.yml -p passwd_if up
docker-compose -f compose/docker-compose.yml -f compose/prod-compose.yml -p passwd_if up -d
```