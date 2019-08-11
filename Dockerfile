FROM debian:stretch

RUN apt-get update -y && apt-get install -y libssl-dev ca-certificates

COPY target/release/smith /usr/local/bin/smith
COPY target/release/smith-host /usr/local/bin/smith-host
COPY target/release/smith-whoami /usr/local/bin/smith-whoami
