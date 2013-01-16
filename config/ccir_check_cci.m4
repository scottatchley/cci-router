AC_DEFUN([CCIR_CHECK_CCI],[
    AC_ARG_WITH([cci], [AS_HELP_STRING([--with-cci=DIR],
                [Specify the location of the CCI installation.])])
    CCIR_CHECK_WITHDIR([cci],[$with_cci], [include/cci.h])
    AC_ARG_WITH([cci-libdir], [AC_HELP_STRING([--with-cci-libdir=DIR],
		 [Search for CCI libraries in DIR])])
    CCIR_CHECK_WITHDIR([cci-libdir],[$with_cci_libdir], [libcci*])

    AS_IF([test ! -z "$with_cci" -a "$with_cci" != "yes"],
          [cci_dir="$with_cci"])
    AS_IF([test ! -z "$with_cci_libdir" -a "$with_cci_libdir" != "yes"],
          [cci_libdir="$with_cci_libdir"])

    CPPFLAGS_save="$CPPFLAGS"
    AS_IF([test ! -z "$cci_dir"],
          AC_SUBST([CPPFLAGS],["-I$cci_dir/include $CPPFLAGS_save"]))
    LDFLAGS_save="$LDFLAGS"
    AS_IF([test ! -z "$cci_libdir"],
          AC_SUBST([LDFLAGS],["-L$cci_libdir $LDFLAGS_save"]))
    AS_IF([test ! -z "$cci_dir" -a -z "$cci_libdir"],
          AC_SUBST([LDFLAGS],["-L$cci_dir/lib $LDFLAGS_save"]))

    AC_CHECK_LIB([cci], [cci_init], , AC_MSG_ERROR([Unable to locate CCI installation]))
])
