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
AC_SEARCH_LIBS([config_init], [config], , AC_MSG_ERROR([libconfig not found]))
AC_SEARCH_LIBS([PQconnectdb], [pq], , AC_MSG_ERROR([libpq not found]))

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
