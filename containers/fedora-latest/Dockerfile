FROM fedora:latest
ENV container=docker

RUN groupadd -g 288 kdcproxy ; useradd -u 288 -g 288 -c 'IPA KDC Proxy User' -d / -s '/sbin/nologin' kdcproxy
RUN groupadd -g 289 ipaapi; useradd -u 289 -g 289 -c 'IPA Framework User' -r -d / -s '/sbin/nologin' ipaapi

RUN ln -s /bin/false /usr/sbin/systemd-machine-id-setup

RUN rm -fv /var/cache/dnf/metadata_lock.pid; \
dnf makecache; \
dnf --assumeyes install \
    /usr/bin/python3 \
    /usr/bin/python3-config \
    /usr/bin/dnf-3 \
    sudo \
    bash \
    systemd \
    procps-ng \
    iproute \
    sudo \
    nss \
    freeipa-server python3-libselinux freeipa-server-dns freeipa-server-trust-ad freeipa-client \
    firewalld \
    && \
dnf clean all;

ENTRYPOINT [ "/usr/sbin/init" ]
STOPSIGNAL RTMIN+3

RUN rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*; \
    rm -rf /var/cache/dnf/;


RUN rmdir -v /etc/systemd/system/multi-user.target.wants \
	&& mkdir /etc/systemd/system/container-ipa.target.wants \
	&& ln -s /etc/systemd/system/container-ipa.target.wants /etc/systemd/system/multi-user.target.wants
RUN systemd-tmpfiles --remove --create

RUN mv /usr/bin/nisdomainname /usr/bin/nisdomainname.orig
ADD hostnamectl-wrapper /usr/bin/nisdomainname
ADD 00-ipv6.conf /etc/sysctl.d/00-ipv6.conf

EXPOSE 53/udp 53 80 443 389 636 88 464 88/udp 464/udp 123/udp

CMD ["/usr/sbin/init"]
