#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.0])
AC_INIT(mailfilter, 0.1, support@mindbit.ro)
AM_INIT_AUTOMAKE(mailfilter, 0.1)
AC_OUTPUT(Makefile src/Makefile)
AC_CONFIG_SRCDIR([src/mailfilter.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([BIO_ctrl], [crypto], , AC_MSG_ERROR([libcrypto not found]))
AC_SEARCH_LIBS([PQconnectdb], [pq], , AC_MSG_ERROR([libpq not found]))
AC_SEARCH_LIBS([JS_NewObject], [mozjs185 mozjs], , AC_MSG_ERROR([libmozjs not found]))

## Fix for debian
CFLAGS="$CFLAGS -I/usr/include/postgresql"

## Special check for SpiderMonkey
AC_MSG_CHECKING(for jsapi.h)

found="no"
for sm_path in /usr/include/js \
		/usr/include/mozjs \
		/usr/include/smjs; do
	if test -x $sm_path && test "$found"=="no"; then
		CFLAGS="$CFLAGS -I$sm_path"
		found="yes"
		break;
  	fi
done

if test "$found" = "yes"; then
	AC_MSG_RESULT(ok)
else
	AC_MSG_ERROR(jsapi.h not found)
fi

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
