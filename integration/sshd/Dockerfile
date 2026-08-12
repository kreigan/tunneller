FROM alpine:3.21

RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && adduser -D -h /home/tester -s /bin/sh tester \
    && passwd -d tester \
    && mkdir -p /home/tester/.ssh \
    && chmod 700 /home/tester/.ssh \
    && chown -R tester:tester /home/tester

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
