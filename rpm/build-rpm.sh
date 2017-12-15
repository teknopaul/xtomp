#!/bin/bash -e
#
# Build the .rpm package
#
if [ `id -u` != "0" ]
then
    sudo $0
    exit $?
fi

#
# The package name
#
NAME=xtomp
ARCH=`uname -m`

#
# Select the files to include
#
cd `dirname $0`/..
PROJECT_ROOT=`pwd`

. ./version
sed -e "s/@PACKAGE_VERSION@/${VERSION}/" rpm/xtomp-src.spec.in > rpm/xtomp-src.spec

mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

tar -z -v -c --transform "s,^,xtomp-$VERSION/," -f /root/rpmbuild/SOURCES/xtomp-$VERSION.tar.gz auto conf configure deploy docs lic script src version

#
# Build the .rpm
#
rpmbuild -bb rpm/xtomp-src.spec

test -f ${NAME}-${VERSION}-1.${ARCH}.rpm

echo "built ${NAME}-${VERSION}-1.${ARCH}.rpm"
