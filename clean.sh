#!/bin/bash

[ -f Makefile ] && make distclean
rm -rf aclocal.m4 autom4te.cache config.h.in configure depcomp missing install-sh Makefile.in src/Makefile.in AUTHORS COPYING INSTALL NEWS README ChangeLog
