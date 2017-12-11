#!/bin/bash -e
#
# Copy VERSION from master location in ../version to hardcoded locations in the code.
#

cd $(dirname $0)

cd ..
. version

sed -i "s/^#define XTOMP_VERSION_MAJOR   [0-9][0-9]*/#define XTOMP_VERSION_MAJOR   $VERSION_MAJOR/" src/xtomp/xtomp.h
sed -i "s/^#define XTOMP_VERSION_MINOR   [0-9][0-9]*/#define XTOMP_VERSION_MINOR   $VERSION_MINOR/" src/xtomp/xtomp.h

sed -i "s/server:xtomp\/[0-9][0-9]*\.[0-9][0-9]*/server:xtomp\/$VERSION/" src/xtomp/xtomp_response.c

#
# Breaks changelog, using perforce for change control.
#
if [ -f deploy/RPM/xtomp.spec.in ]
then
  sed -i "s/teknopaul.com> [0-9][0-9]*\.[0-9][0-9]*/teknopaul.com> $VERSION/" deploy/RPM/xtomp.spec.in
fi

#
# .deb build
#
if [ -f deploy/DEBIAN/control.in ]
then
  sed -e "s/@PACKAGE_VERSION@/${VERSION}/" deploy/DEBIAN/control.in >  deploy/DEBIAN/control
fi

if [ -f deploy/xtomp.recipe.in ]
then
  . deploy/ppa-version
  sed -e "s/VERSION/${VERSION}-${PPA_VERSION}/" deploy/xtomp.recipe.in > deploy/xtomp.recipe
fi

#
# github build has deploy/debian in lowercase to differentiate
#
if [ -f debian/control.in ]
then
  . deploy/ppa-version

  sed -e "s/@PACKAGE_VERSION@/${VERSION}-${PPA_VERSION}/" debian/control.in >  debian/control

fi

