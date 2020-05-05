# SimpleSAMLPHP base image

[simplesamlphp](https://simplesamlphp.org/) docker base image for e-UCM projects. This image includes:

- PHP 7.3
- SimplesamlPHP
- MSSMTP configured to be used as sendmail replacement and configured to support PHP mail function.

## SSL certificate for development

The `docker-compose.yml` depends on a ssl certificate. Unfortunately we can not use LetsEncrypt for development, so it is needed to create a self-signed certificate for Traefik. Moreover it is needed to install that self-signed certificate inside the browsers certificate manager or the OS certificate manager.

Instead generating and configure the certificate manually using [openssl](https://www.openssl.org/), [EasyRSA](https://github.com/OpenVPN/easy-rsa) or [cfssl](https://github.com/cloudflare/cfssl), you can use [mkcert](https://github.com/FiloSottile/mkcert).