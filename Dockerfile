FROM golang:1.19.9-alpine3.17 as builder

WORKDIR $GOPATH/src/web

COPY server.go .
COPY sshs.go .

RUN apk add --no-cache git && set -x && \
    go mod init && go get -d -v
RUN CGO_ENABLED=0 GOOS=linux go build -o /server server.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /sshs sshs.go

FROM alpine
RUN apk update && apk add --no-cache \
  curl openssh openssh-server zip unzip net-tools  iputils iproute2 tcpdump git vim bash mysql-client redis \
  && mkdir -p /var/run/sshd \
  && sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
  && sed -ri 's/^#?ClientAliveInterval\s+.*/ClientAliveInterval 60/' /etc/ssh/sshd_config \
  && sed -ri 's/^#?ClientAliveCountMax\s+.*/ClientAliveCountMax 1000/' /etc/ssh/sshd_config \
  && sed -ri 's/^#?TCPKeepAlive\s+.*/TCPKeepAlive yes/' /etc/ssh/sshd_config \
  && sed -ri 's/^#?PasswordAuthentication\s+.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
  && sed -ri 's/^#PubkeyAuthentication\s+.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
  && echo 'root:root@1234' |chpasswd \
  && ssh-keygen -t dsa -P "" -f /etc/ssh/ssh_host_dsa_key  \
  && ssh-keygen -t rsa -P "" -f /etc/ssh/ssh_host_rsa_key  \
  && ssh-keygen -t ecdsa -P "" -f /etc/ssh/ssh_host_ecdsa_key  \
  && ssh-keygen -t ed25519 -P "" -f /etc/ssh/ssh_host_ed25519_key  \
  && mkdir /root/.ssh 

ADD . /
WORKDIR /
COPY --from=builder /server .
COPY --from=builder /sshs .
copy . .
CMD ["/bin/bash", "run.sh"]

EXPOSE 80
