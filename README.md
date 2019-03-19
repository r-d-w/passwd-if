# passwd-if

Python/Flask Web App for managing user passwords including self service.

## initial configuration

You will need to provide a configuration file for apache and the password interface python application. You can copy the examples in the conf directory and replace the <PLACEHOLDERS> with values appropriate for you environment.  There are a number of sensitive fields that you can chose to store in the configuration files, but it is not recommmended.  Instead, you should pass in your secrets via environment variables or through files in the secrets directory.

```
cp conf/apache2.conf.example conf/apache2.conf
cp conf/passwd_interface_conf.json.example conf/passwd_interface_conf.json
$EDITOR conf/apache2.conf
$EDITOR conf/passwd_interface_conf.json
```
## Sensitive data

## Development setup with debugger

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

## development setup wtih apache
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

# setting up active directory password policy objects (assumes Windows Server 2016+)
- Create group for each password length policy you have, default being most restrictive min
- Open Active Directory Administration Center
- Navigate through <YOUR_DOM> => System => Password Setting Container
- Task => New => Password Setting
- Name something logical and match settings appropriate to the policy from passwd-if conf
- Add in the correct group for this policy

# Setting ub Kerberos for SSO with Active Directory
- Create a krb5.conf, follow the example in the conf dir, adjust values as necessary
- Make sure there is a service principal for the http server attached to a user for auth 
```
setspn -S HTTP/passwd.corp.example.com
```
- Make keytab file that can be read in linux, if re-using the passwd app user, re-use the password as well.
```
ktpass -out <KEYTAB_FILE> -ptype KRB5_NT_PRINCIPAL /mapuser app_passwd-if -pass <APP_USER_PASSWORD> -princ HTTP/passwd.corp.example.com@CORP.EXAMPLE.COM
```
