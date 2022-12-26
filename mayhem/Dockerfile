FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y ccache flex bison libnl-3-dev build-essential \
    libnl-genl-3-dev libnl-route-3-dev libgeoip-dev \
    libnetfilter-conntrack-dev libncurses5-dev liburcu-dev \
    libnacl-dev libpcap-dev zlib1g-dev libcli-dev libnet1-dev

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8
RUN make install

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libcli-dev libnet1-dev
COPY --from=builder /install /install
