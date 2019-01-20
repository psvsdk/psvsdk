FROM alpine as builder
WORKDIR /root
COPY . .
RUN apk add musl-dev gcc make
#RUN wget https://github.com/psvsdk/psvsdk/archive/v0.1.tar.gz -qO- | tar -xvz
RUN make

FROM frolvlad/alpine-glibc
RUN wget https://github.com/vitasdk/vita-headers/archive/v0.1.tar.gz -qO- | tar -xz --strip-components=1 -C /usr/share/
RUN wget https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/6-2017q2/gcc-arm-none-eabi-6-2017-q2-update-linux.tar.bz2 -qO- | tar xj --strip-components=1 -C /usr/
WORKDIR /root
COPY --from=builder /root/bin /usr/bin
ENTRYPOINT ["/bin/sh"]
