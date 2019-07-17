FROM debian:stretch

RUN apt-get update -y && apt-get install -y libssl-dev ca-certificates

COPY target/executables/smith /usr/local/bin/smith
COPY target/executables/smith-host /usr/local/bin/smith-host
COPY target/executables/smith-whoami /usr/local/bin/smith-whoami
