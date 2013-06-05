# -*- shell-script -*-
#
# Copyright © 2013 UT-Battelle, LLC.  All rights reserved.
#
# See COPYING in top-level directory.
# 
# Additional copyrights may follow
# 
# $HEADER$
#

AC_INIT([cci-router], [0.1], [cci-info@lists.cci-forum.com])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([./config])
AC_CONFIG_MACRO_DIR([./config])

AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects foreign tar-ustar -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_MKDIR_P
AM_PROG_CC_C_O

AC_CONFIG_HEADERS([include/config.h])

CCIR_DEFINE_ARGS
CCIR_CHECK_CCI

AC_CONFIG_FILES([Makefile include/Makefile src/Makefile etc/Makefile etc/ccir/Makefile])

AC_OUTPUT
