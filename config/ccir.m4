dnl -*- Autoconf -*-
dnl
dnl Copyright © 2010 Cisco Systems, Inc.  All rights reserved.
dnl Copyright © 2013 UT-Battelle, LLC.  All rights reserved.
dnl

# Define CCIR configure command line arguments
AC_DEFUN([CCIR_DEFINE_ARGS],[
    AC_ARG_ENABLE([picky],
        [AC_HELP_STRING([--enable-picky],
                        [Turn on maintainer-level compiler pickyness])])
    AS_IF([test -d $srcdir/.hg -o -d $srcdir/.svn -o -d $srcdir/.git],
          [CCIR_DEVEL_BUILD=yes
           AS_IF([test "$enable_picky" = ""],
                 [AC_MSG_WARN([Developer build: enabling pickyness by default])
                  enable_picky=yes])])
    # If we want picky, be picky.
    CCIR_C_COMPILER_VENDOR([ccir_cc_vendor])
    AS_IF([test "$enable_picky" = yes -a "$ccir_cc_vendor" = "gnu"],
          [ccir_add="-Wall -Wundef -Wsign-compare"
           ccir_add="$ccir_add -Wmissing-prototypes -Wstrict-prototypes"
           ccir_add="$ccir_add -Wcomment -pedantic"
           ccir_add="$ccir_add -Werror-implicit-function-declaration "
           ccir_add="$ccir_add -Wstrict-prototypes"
           CFLAGS="$CFLAGS $ccir_add"
           CCIR_UNIQ(CFLAGS)
           AC_MSG_WARN([$ccir_add has been added to CFLAGS (--enable-picky)])
           unset ccir_add])
    AS_IF([test "$CCIR_DEVEL_BUILD" = "yes"],
          [AC_MSG_WARN([-g has been added to CFLAGS (developer build)])
           CFLAGS="$CFLAGS -g"])

    # Look for valgrind
    AC_ARG_ENABLE(valgrind,
                  AC_HELP_STRING(--enable-valgrind, enable Valgrind hooks),
                  enable_valgrind=yes)
    if test x$enable_valgrind = xyes ; then
        AC_CHECK_DECLS([VALGRIND_MAKE_MEM_NOACCESS],
                       [AC_MSG_NOTICE(activating Valgrind hooks)],
                       [:],
                       [[#include <valgrind/memcheck.h>]])
    fi

    # Add relevant -I's for our internal header files
    CPPFLAGS="$CPPFLAGS -I$srcdir/../include"
])
