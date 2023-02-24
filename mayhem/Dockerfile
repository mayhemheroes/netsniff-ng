FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y ccache flex bison libnl-3-dev build-essential \
    libnl-genl-3-dev libnl-route-3-dev libgeoip-dev \
    libnetfilter-conntrack-dev libncurses5-dev liburcu-dev \
    libnacl-dev libpcap-dev zlib1g-dev libcli-dev libnet1-dev clang

COPY . /repo
WORKDIR /repo
RUN ./configure --prefix=/install
RUN make -j8 -n | tee out
RUN make -j8
RUN make install
RUN rm /repo/netsniff-ng/netsniff-ng.o
RUN clang++ /repo/mayhem/fuzz_str2fqdn.cpp -fsanitize=fuzzer,address /repo/netsniff-ng/*.o -I /repo -o /fuzz  -lpthread -lpcap -lGeoIP -lz -lnl-3 -lnl-genl-3 -lnl-3 -lnl-route-3 -lnl-3

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libpcap-dev libcli-dev libnet1-dev libgeoip-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_str2fqdn
