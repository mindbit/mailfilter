AC_PREREQ([2.61])
AC_INIT([mailfilter], [1.0], [support@mindbit.ro])

# Detect missing Autoconf Archive library in the system
m4_pattern_forbid([^AX_])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
AX_COMPILER_VENDOR
AX_COMPILER_VERSION

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
AC_CHECK_HEADERS_ONCE([arpa/inet.h])
AC_CHECK_SIZEOF([void *])
LT_INIT

CFLAGS="-Wall $CFLAGS"

#
# additional configure arguments
#

AC_ARG_WITH(duktape,
    AC_HELP_STRING([--with-js-include=DIR], [search for Duktape headers in DIR]),
    [
        DUKTAPE="$withval"
    ]
)

AC_ARG_WITH(jsmisc,
    AC_HELP_STRING([--with-jsmisc=DIR], [search for jsmisc in DIR]),
    [
        JSMISC="$withval"
    ]
)

#
# Checks for libraries
#

AC_SEARCH_LIBS([BIO_ctrl], [crypto], , AC_MSG_ERROR([libcrypto not found]))
# FIXME res_nquery expands to __res_nquery (see /usr/include/resolv.h), so checking for
# res_nquery fails because that's not a symbol; need to check this in a portable way
AC_SEARCH_LIBS([__res_nquery], [resolv], , AC_MSG_ERROR([libresolv not found]))

#
# test for Duktape
#

if test -n "$DUKTAPE" ; then
    CPPFLAGS="-I$DUKTAPE $CPPFLAGS"
fi
AC_CHECK_HEADER(duktape.h,[],[],-)
if test "x$ac_cv_header_duktape_h" != xyes ; then
    AC_MSG_ERROR([duktape.h not found])
fi
LIBS="-lm $LIBS"
AC_CHECK_LIB([duktape],[duk_create_heap],[],[
    AC_MSG_ERROR([Duktape library not found])
])

#
# test for jsmisc
#

if test -n "$JSMISC" ; then
    CPPFLAGS="-I$JSMISC $CPPFLAGS"
fi
AC_CHECK_HEADER(jsmisc.h,[],[],-)
if test "x$ac_cv_header_jsmisc_h" != xyes ; then
    AC_MSG_ERROR([jsmisc.h not found])
fi

AC_CHECK_LIB([jsmisc],[js_misc_init],[],[
    AC_MSG_ERROR([jsmisc library not found])
])

#
# test for libspf2
#

AC_CHECK_HEADER(spf2/spf.h,[],[],[
    #ifdef HAVE_SYS_TYPES_H
    #include <sys/types.h>
    #endif
    #ifdef HAVE_ARPA_INET_H
    #include <arpa/inet.h>
    #endif
])

if test "x$ac_cv_header_spf2_spf_h" = xyes; then
    AC_CHECK_LIB([spf2],[SPF_server_new],[
        AH_CHECK_LIB([spf2])
        AC_DEFINE([HAVE_LIBSPF2])
        LIBS="-lspf2 $LIBS"
        found_spf2=yes
    ],[])
fi

AM_CONDITIONAL([HAVE_SPF2], [test x$found_spf2 = xyes])

#
# Debug mode
#

AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug], [Enable debugging mode]))

AS_IF([test "x$enable_debug" = "xyes"], [
     CFLAGS="$CFLAGS -DJS_DEBUG"
])

#
# Git versioning
#

AC_DEFINE_UNQUOTED(VERSION_STR,
    ["mailfilter `git describe` ($host, $ax_cv_c_compiler_vendor cc $ax_cv_c_compiler_version, `expr $ac_cv_sizeof_void_p \* 8`-bit)"],
    [A string containing the version number, platform, and C compiler])

AC_OUTPUT
