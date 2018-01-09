While developing secrets can go here.  For production deployments, use your best judgement getting your secrets into your environment.

You will want to create a `certs` directory that contains a `server.crt` and `server.key` file for SSL termination.  `server.crt` should contain the entire chain, server cert first, encoded in PEM. If you choose not to include a certs directory, the image will default to using the randomly generated ones installed with ssl-cert.  Fine for dev, wouldn't recommend it in prod.

The secret key for Flask should be a suitably random number.  It needs to be base 64 encode.  I like using
```
openssl rand -base64 256 | tr -d '\n'
```