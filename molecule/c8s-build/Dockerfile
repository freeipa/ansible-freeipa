FROM quay.io/centos/centos:stream8
ENV container=docker

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
    iproute && \
dnf clean all; \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*; \
rm -rf /var/cache/dnf/;

STOPSIGNAL RTMIN+3

VOLUME ["/sys/fs/cgroup"]

CMD ["/usr/sbin/init"]
