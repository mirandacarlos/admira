FROM php:8.4-apache

# Instalar dependencias y extensiones
RUN apt-get update && apt-get install -y \
    libzip-dev zip curl \
    && docker-php-ext-install pdo pdo_mysql zip \
    && pecl install xdebug \
    && docker-php-ext-enable xdebug

# Configurar Xdebug
RUN echo "xdebug.mode=debug" > /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.start_with_request=yes" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.client_host=host.docker.internal" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.client_port=9003" >> /usr/local/etc/php/conf.d/xdebug.ini
