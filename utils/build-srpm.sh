#!/bin/bash

git_version=$(git describe --tags | sed -e "s/^v//")
version=${git_version%%-*}
release=${git_version#*-}
release=${release//-/_}

date=$(date "+%a %b %e %Y")
topdir=$(dirname $0)

sed -e "s/@@VERSION@@/$version/g" -e "s/@@RELEASE@@/$release/g" -e "s/@@DATE@@/$date/g" $topdir/ansible-freeipa.spec.in > ansible-freeipa.spec

git archive --format=tar --prefix=ansible-freeipa-${version}-${release}/ 'HEAD' | bzip2 -c > ansible-freeipa-${version}-${release}.tar.bz2

rpmbuild --define "_sourcedir $PWD" -bs ansible-freeipa.spec
