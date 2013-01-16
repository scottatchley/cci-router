dnl -*- shell-script -*-
dnl
dnl Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
dnl                         University Research and Technology
dnl                         Corporation.  All rights reserved.
dnl Copyright (c) 2004-2005 The University of Tennessee and The University
dnl                         of Tennessee Research Foundation.  All rights
dnl                         reserved.
dnl Copyright (c) 2004-2005 High Performance Computing Center Stuttgart, 
dnl                         University of Stuttgart.  All rights reserved.
dnl Copyright (c) 2004-2005 The Regents of the University of California.
dnl                         All rights reserved.
dnl Copyright (c) 2007      Sun Microsystems, Inc.  All rights reserved.
dnl Copyright (c) 2013      UT-Battelle, LLC.  All rights reserved.
dnl Copyright (c) 2009-2010 Cisco Systems, Inc.  All rights reserved.
dnl
dnl $COPYRIGHT$
dnl 
dnl Additional copyrights may follow
dnl 
dnl $HEADER$
dnl

AC_DEFUN([CCIR_CONFIGURE_SETUP],[

# Some helper script functions.  Unfortunately, we cannot use $1 kinds
# of arugments here because of the m4 substitution.  So we have to set
# special variable names before invoking the function.  :-\

ccir_show_title() {
  cat <<EOF

###
### ${1}
###
EOF
}


ccir_show_subtitle() {
  cat <<EOF

*** ${1}
EOF
}


ccir_show_subsubtitle() {
  cat <<EOF

+++ ${1}
EOF
}

ccir_show_subsubsubtitle() {
  cat <<EOF

--- ${1}
EOF
}

#
# Save some stats about this build
#

CCIR_CONFIGURE_USER="`whoami`"
CCIR_CONFIGURE_HOST="`hostname | head -n 1`"
CCIR_CONFIGURE_DATE="`date`"

#
# Save these details so that they can be used in ccir_info later
#
AC_SUBST(CCIR_CONFIGURE_USER)
AC_SUBST(CCIR_CONFIGURE_HOST)
AC_SUBST(CCIR_CONFIGURE_DATE)])dnl

dnl #######################################################################
dnl #######################################################################
dnl #######################################################################

AC_DEFUN([CCIR_UNIQ],[
# 1 is the variable name to be uniq-ized
ccir_name=$1

# Go through each item in the variable and only keep the unique ones

ccir_count=0
for val in ${$1}; do
    ccir_done=0
    ccir_i=1
    ccir_found=0

    # Loop over every token we've seen so far

    ccir_done="`expr $ccir_i \> $ccir_count`"
    while test "$ccir_found" = "0" -a "$ccir_done" = "0"; do

	# Have we seen this token already?  Prefix the comparison with
	# "x" so that "-Lfoo" values won't be cause an error.

	ccir_eval="expr x$val = x\$ccir_array_$ccir_i"
	ccir_found=`eval $ccir_eval`

	# Check the ending condition

	ccir_done="`expr $ccir_i \>= $ccir_count`"

	# Increment the counter

	ccir_i="`expr $ccir_i + 1`"
    done

    # If we didn't find the token, add it to the "array"

    if test "$ccir_found" = "0"; then
	ccir_eval="ccir_array_$ccir_i=$val"
	eval $ccir_eval
	ccir_count="`expr $ccir_count + 1`"
    else
	ccir_i="`expr $ccir_i - 1`"
    fi
done

# Take all the items in the "array" and assemble them back into a
# single variable

ccir_i=1
ccir_done="`expr $ccir_i \> $ccir_count`"
ccir_newval=
while test "$ccir_done" = "0"; do
    ccir_eval="ccir_newval=\"$ccir_newval \$ccir_array_$ccir_i\""
    eval $ccir_eval

    ccir_eval="unset ccir_array_$ccir_i"
    eval $ccir_eval

    ccir_done="`expr $ccir_i \>= $ccir_count`"
    ccir_i="`expr $ccir_i + 1`"
done

# Done; do the assignment

ccir_newval="`echo $ccir_newval`"
ccir_eval="$ccir_name=\"$ccir_newval\""
eval $ccir_eval

# Clean up

unset ccir_name ccir_i ccir_done ccir_newval ccir_eval ccir_count])dnl

dnl #######################################################################
dnl #######################################################################
dnl #######################################################################

# Macro that serves as an alternative to using `which <prog>`. It is
# preferable to simply using `which <prog>` because backticks (`) (aka
# backquotes) invoke a sub-shell which may source a "noisy"
# ~/.whatever file (and we do not want the error messages to be part
# of the assignment in foo=`which <prog>`). This macro ensures that we
# get a sane executable value.
AC_DEFUN([CCIR_WHICH],[
# 1 is the variable name to do "which" on
# 2 is the variable name to assign the return value to

CCIR_VAR_SCOPE_PUSH([ccir_prog ccir_file ccir_dir ccir_sentinel])

ccir_prog=$1

IFS_SAVE=$IFS
IFS="$PATH_SEPARATOR"
for ccir_dir in $PATH; do
    if test -x "$ccir_dir/$ccir_prog"; then
        $2="$ccir_dir/$ccir_prog"
        break
    fi
done
IFS=$IFS_SAVE

CCIR_VAR_SCOPE_POP
])dnl
