# SimpleSAMLPHP base image

[simplesamlphp](https://simplesamlphp.org/) docker base image for e-UCM projects. This image includes:

- PHP 7.4
- SimplesamlPHP
- MSSMTP configured to be used as sendmail replacement and configured to support PHP mail function.

## SSL certificate for development

The `docker-compose.yml` depends on a ssl certificate. Unfortunately we can not use LetsEncrypt for development, so it is needed to create a self-signed certificate for Traefik. Moreover it is needed to install that self-signed certificate inside the browsers certificate manager or the OS certificate manager.

Instead generating and configure the certificate manually using [openssl](https://www.openssl.org/), [EasyRSA](https://github.com/OpenVPN/easy-rsa) or [cfssl](https://github.com/cloudflare/cfssl), you can use [mkcert](https://github.com/FiloSottile/mkcert).

As part of the setup process, the `traefik` container generates an `mkcert` CA and generates certificates for all other containers. If you want to avoid your browser error about the unrecognized CA, you have to import the CA cert `./data/traefik/ssl/ca/rootCA.pem`.