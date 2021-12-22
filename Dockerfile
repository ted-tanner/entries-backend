FROM rust:1.56.1-slim-bullseye

COPY entrypoint.sh /scripts/entrypoint.sh
RUN ["chmod", "+x", "/scripts/entrypoint.sh"]

RUN apt-get update -y && apt-get install -y libpq-dev && apt-get install -y clang

WORKDIR /server

EXPOSE 9000

ENTRYPOINT ["/scripts/entrypoint.sh"]