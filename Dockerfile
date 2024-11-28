FROM php:7.4.33-apache-bullseye

# Optimize recurrent builds by using a helper container runing apt-cache
ARG USE_APT_CACHE
ENV USE_APT_CACHE=${USE_APT_CACHE}
RUN ([ ! -z $USE_APT_CACHE ] && echo 'Acquire::http { Proxy "http://172.17.0.1:3142"; };' >> /etc/apt/apt.conf.d/01proxy \
    && echo 'Acquire::HTTPS::Proxy "false";' >> /etc/apt/apt.conf.d/01proxy) || true

# Configure msmtp in PHP to send mails
RUN set -eux; \
	apt-get update; \
    apt-get install -y --no-install-recommends \
        msmtp \
        wget \
    ; \
    rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/*; \
    { \
        echo 'sendmail_path="/usr/bin/msmtp -C /etc/msmtp-php.conf --logfile - -a default -t"'; \
    } > /usr/local/etc/php/conf.d/msmtp.ini

# set recommended PHP.ini settings
# see https://secure.php.net/manual/en/opcache.installation.php
RUN set -eux; \
	docker-php-ext-enable opcache; \
	{ \
		echo 'opcache.memory_consumption=128'; \
		echo 'opcache.interned_strings_buffer=8'; \
		echo 'opcache.max_accelerated_files=4000'; \
		echo 'opcache.revalidate_freq=2'; \
	} > /usr/local/etc/php/conf.d/opcache-recommended.ini

# Configure PHP sessions storage
RUN set -eux; \
    mkdir -p /var/lib/php/sessions; \
    chgrp www-data /var/lib/php/sessions; \
    chmod u=rwx,g=wx,o= /var/lib/php/sessions; \
    { \
        echo 'session.save_path="/var/lib/php/sessions"'; \
    } > /usr/local/etc/php/conf.d/sessions.ini

# Configure PHP error logging to /dev/stdout
RUN set -eux; \
    { \
# https://www.php.net/manual/en/errorfunc.constants.php
# https://github.com/docker-library/wordpress/issues/420#issuecomment-517839670
		echo 'error_reporting = E_ERROR | E_WARNING | E_PARSE | E_CORE_ERROR | E_CORE_WARNING | E_COMPILE_ERROR | E_COMPILE_WARNING | E_RECOVERABLE_ERROR'; \
		echo 'display_errors = Off'; \
		echo 'display_startup_errors = Off'; \
		echo 'log_errors = On'; \
		echo 'error_log = /dev/stderr'; \
		echo 'log_errors_max_len = 1024'; \
		echo 'ignore_repeated_errors = On'; \
		echo 'ignore_repeated_source = Off'; \
		echo 'html_errors = Off'; \
    } > /usr/local/etc/php/conf.d/error-log.ini

ENV SIMPLESAMLPHP_VERSION=1.19.9
ENV SIMPLESAMLPHP_URL=https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SIMPLESAMLPHP_VERSION}/simplesamlphp-${SIMPLESAMLPHP_VERSION}.tar.gz
ENV SIMPLESAMLPHP_SHA256=f7571dfe363423744d36e47c90e6dd1b1a96acab8b15383b3731e504b6545a9d
ENV SIMPLESAMLPHP_HOME=/usr/share/simplesamlphp

# Installation instructions adapted from Debian package
RUN set -eux; \
    curl -fsSL "$SIMPLESAMLPHP_URL" -o /tmp/simplesamlphp.tar.gz; \
    echo "$SIMPLESAMLPHP_SHA256 /tmp/simplesamlphp.tar.gz" | sha256sum -c -; \
    tar xf /tmp/simplesamlphp.tar.gz  -C /usr/share; \
    mv "$SIMPLESAMLPHP_HOME-$SIMPLESAMLPHP_VERSION" "$SIMPLESAMLPHP_HOME"; \
    for dir in \
        /etc/simplesamlphp \
        /var/cache/simplesamlphp \
        /var/lib/simplesamlphp/data \
        /var/lib/simplesamlphp/sessions \
        /var/log/simplesamlphp \
    ; do \
        mkdir -p ${dir}; \
    done; \
    for dir in \
        config \
        metadata \
    ; do \
        rm -fr "$SIMPLESAMLPHP_HOME/${dir}"; \
    done; \
    ln -s /etc/simplesamlphp "$SIMPLESAMLPHP_HOME/config"; \
    chgrp www-data \
        /var/cache/simplesamlphp \
        /var/lib/simplesamlphp/data \
		/var/lib/simplesamlphp/sessions \
        /var/log/simplesamlphp \
    ; \
	chmod u=rwx,g=wx,o= \
        /var/cache/simplesamlphp \
        /var/lib/simplesamlphp/data \
        /var/lib/simplesamlphp/sessions \
		/var/log/simplesamlphp; \
    rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/*;

COPY overlay /
RUN set -eux; \
    cd ${SIMPLESAMLPHP_HOME}; \
    find /var/tmp/patches/simplesamlphp -type f -print0 | xargs -0 -n1 patch --verbose -p1 -i; \
    a2enmod remoteip; \
    a2enmod headers; \
    a2enconf remoteip; \
    rm -fr /tmp/* /var/tmp/*;
#
#RUN set -eux; \
#    { \
#        echo 'auto_prepend_file=/etc/simplesamlphp/trust-forwarded-headers.php'; \
#    } > /usr/local/etc/php/conf.d/trust-forwarded-headers.ini

VOLUME ["/etc/simplesamlphp", "/var/lib/simplesamlphp", "/var/log/simplesamlphp", "/var/cache/simplesamlphp"]

ENTRYPOINT ["/usr/local/bin/entrypoint"]
CMD ["/usr/local/bin/server"]
