#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.0])
AC_INIT(mailfilter, 0.1, support@mindbit.ro)
AM_INIT_AUTOMAKE(mailfilter, 0.1)
AC_OUTPUT(Makefile src/Makefile)
AC_CONFIG_SRCDIR([src/mailfilter.c])
AC_CONFIG_HEADERS([config.h])

AC_COMPILE_IFELSE(
     [AC_LANG_PROGRAM([[#include <libconfig.h>]],
                      [[const char *value;
config_t cf;
value = config_lookup_string(&cf, "key");]])], [], [AC_DEFINE([LIBCONFIG_NEW_API], [1], [Libconfig API changes])])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([config_init], [config], , AC_MSG_ERROR([libconfig not found]))
AC_SEARCH_LIBS([BIO_ctrl], [crypto], , AC_MSG_ERROR([libcrypto not found]))
AC_SEARCH_LIBS([PQconnectdb], [pq], , AC_MSG_ERROR([libpq not found]))

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
