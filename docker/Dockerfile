FROM alpine:3.18 AS builder

ARG BUILD_DEPENDENCIES="build-base \
    libffi-dev \
    libpq-dev \
    libxml2-dev \
    mariadb-connector-c-dev \
    # openldap-dev \
    python3-dev \
    xmlsec-dev \
    npm \
    yarn \
    cargo \
    python3-poetry"

ENV LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    FLASK_APP=/build/powerdnsadmin/__init__.py

# Get dependencies
# py3-pip should not belong to BUILD_DEPENDENCIES. Otherwise, when we remove
# them with "apk del" at the end of build stage, the python requests module
# will be removed as well - (Tested with alpine:3.12 and python 3.8.5).
RUN apk add --no-cache ${BUILD_DEPENDENCIES} && \
    apk add --no-cache py3-pip

WORKDIR /build

# We copy just the requirements.txt first to leverage Docker cache
COPY ./pyproject.toml /build/

# Get application dependencies
# RUN pip install --upgrade pip && \
#     pip install --use-pep517 -r requirements.txt
RUN poetry install

# Add sources
COPY . /build

# Prepare assets
RUN yarn install --pure-lockfile --production && \
    yarn cache clean && \
    sed -i -r -e "s|'rcssmin',\s?'cssrewrite'|'rcssmin'|g" /build/powerdnsadmin/assets.py && \
    flask assets build

RUN mv /build/powerdnsadmin/static /tmp/static && \
    mkdir /build/powerdnsadmin/static && \
    cp -r /tmp/static/generated /build/powerdnsadmin/static && \
    cp -r /tmp/static/assets /build/powerdnsadmin/static && \
    cp -r /tmp/static/img /build/powerdnsadmin/static && \
    find /tmp/static/node_modules -name 'webfonts' -exec cp -r {} /build/powerdnsadmin/static \; && \
    find /tmp/static/node_modules -name 'fonts' -exec cp -r {} /build/powerdnsadmin/static \; && \
    find /tmp/static/node_modules/icheck/skins/square -name '*.png' -exec cp {} /build/powerdnsadmin/static/generated \;

RUN { \
      echo "from flask_assets import Environment"; \
      echo "assets = Environment()"; \
      echo "assets.register('js_login', 'generated/login.js')"; \
      echo "assets.register('js_validation', 'generated/validation.js')"; \
      echo "assets.register('css_login', 'generated/login.css')"; \
      echo "assets.register('js_main', 'generated/main.js')"; \
      echo "assets.register('css_main', 'generated/main.css')"; \
    } > /build/powerdnsadmin/assets.py

# Move application
RUN mkdir -p /app && \
    cp -r /build/migrations/ /build/powerdnsadmin/ /build/run.py /app && \
    mkdir -p /app/configs && \
    cp -r /build/configs/docker_config.py /app/configs

# Build image
FROM alpine:3.18

ENV FLASK_APP=/app/powerdnsadmin/__init__.py \
    USER=pda

# RUN apk add --no-cache mariadb-connector-c postgresql-client py3-gunicorn py3-pyldap py3-flask py3-psycopg2 xmlsec tzdata libcap && \
RUN apk add --no-cache mariadb-connector-c postgresql-client py3-gunicorn py3-flask py3-psycopg2 xmlsec tzdata libcap
RUN addgroup -S powerdnsadmin
RUN adduser -S -D -G powerdnsadmin powerdnsadmin
RUN mkdir /data 
RUN chown powerdnsadmin:powerdnsadmin /data
RUN setcap cap_net_bind_service=+ep $(readlink -f /usr/bin/python3)
RUN apk del libcap

COPY --from=builder /usr/bin/flask /usr/bin/
COPY --from=builder /usr/lib/python3.10/site-packages /usr/lib/python3.10/site-packages/
COPY --from=builder --chown=root:powerdnsadmin /app /app/
COPY ./entrypoint.sh /usr/bin/

WORKDIR /app
RUN chown powerdnsadmin:powerdnsadmin ./configs /app && \
    cat ./powerdnsadmin/default_config.py ./configs/docker_config.py > ./powerdnsadmin/docker_config.py

EXPOSE 80/tcp
USER powerdnsadmin
HEALTHCHECK CMD ["wget","--output-document=-","--quiet","--tries=1","http://127.0.0.1/"]
ENTRYPOINT ["entrypoint.sh"]
CMD ["gunicorn","powerdnsadmin:create_app()"]
