# C0F toolkit build environment (throw-away). Debian packages only, from deb.debian.org.
FROM debian:trixie-slim
# optional: docker build --build-arg UA="..." to send a specific HTTP User-Agent from apt
ARG UA=""
RUN if [ -n "$UA" ]; then printf 'Acquire::http::User-Agent "%s";\nAcquire::https::User-Agent "%s";\n' "$UA" "$UA" > /etc/apt/apt.conf.d/99-user-agent; fi \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    make gcc libc6-dev bison flex m4 pkg-config autoconf automake libtool gettext autopoint patch xz-utils bzip2 file ca-certificates perl python3 gawk texinfo \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
