AC_INIT(setools, 3.0, [Tresys Technology <setools@tresys.com>], [setools])
AC_CONFIG_SRCDIR(awish/awish.c)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(setools, 3.0)
AC_GNU_SOURCE
AC_PROG_CC
AC_LANG_C
AC_HEADER_STDC
AC_PROG_RANLIB
AC_PROG_LN_S
AM_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL

libqpol_version=1.0.0
libqpol_soname=libqpol.so.1

libapol_version=3.0.0
libapol_soname=libapol.so.3
libapol_tcl_soname=libapol-tcl.so.3

libpoldiff_version=1.0.0
libpoldiff_soname=libpoldiff.so.1

libsefs_version=3.0.0
libsefs_soname=libsefs.so.3

libseaudit_version=3.0.0

AC_CHECK_SIZEOF(char *)
AC_C_BIGENDIAN
AC_CHECK_FUNCS(rand_r)

AC_ARG_ENABLE(shared, [  --enable-shared         link against shared libapol (default)], enable_shared="$enableval", enable_shared="yes")
AC_MSG_CHECKING([for how to link against libraries])
if test "x${enable_shared}" = xyes; then
    use_shared=yes
    AC_MSG_RESULT(shared)
else
    use_shared=no
    AC_MSG_RESULT(static)
fi

AC_ARG_ENABLE(debug, [  --enable-debug          compile with full debugging support], enable_debug="$enableval")
AC_MSG_CHECKING([for debugging support])
if test "x${enable_debug}" = xyes; then
    CFLAGS="-g3 -gdwarf-2 -O0 -Wall"
    LDFLAGS="-g"
    QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so -Wl,-rpath=$(top_builddir)/libqpol/src'
    APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.a -Wl,-rpath=$(top_builddir)/libapol/src'
    SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.a -Wl,-rpath=$(top_builddir)/libsefs/src'
    POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.a -Wl,-rpath=$(top_builddir)/libpoldiff/src'
    AC_MSG_RESULT(yes)
else
    if test ${use_shared} = yes; then
        QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so'
        APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.so'
        SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.so'
        POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.so'
    else
        QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so'
        APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.a'
        SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.a'
        POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.a'
    fi
    AC_MSG_RESULT(disabled)
fi
QPOL_CFLAGS='-I$(top_srcdir)/libqpol/include'
APOL_CFLAGS='-I$(top_srcdir)/libapol/include'
SEFS_CFLAGS='-I$(top_srcdir)/libsefs/include'
POLDIFF_CFLAGS='-I$(top_srcdir)/libpoldiff/include'
AC_SUBST(QPOL_CFLAGS)
AC_SUBST(APOL_CFLAGS)
AC_SUBST(SEFS_CFLAGS)
AC_SUBST(POLDIFF_CFLAGS)
AC_SUBST(QPOL_LIB_FLAG)
AC_SUBST(APOL_LIB_FLAG)
AC_SUBST(SEFS_LIB_FLAG)
AC_SUBST(POLDIFF_LIB_FLAG)

AC_ARG_ENABLE(profiling, [  --enable-profiling      compile with gcov and gprof profiling support], enable_profiling="$enableval")
AC_MSG_CHECKING([for profiling support])
if test "x${enable_profiling}" = xyes; then
    CFLAGS="-O0 -Wall -ftest-coverage -fprofile-arcs -pg"
    LDFLAGS="$LDFLAGS -lgcov"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(disabled)
fi

dnl ** find the Tcl/Tk development libraries, then find BWidget

TEA_INIT(3.5)
TEA_PATH_TCLCONFIG
TEA_LOAD_TCLCONFIG
AC_MSG_CHECKING([for Tcl 8.4 or greater])
if test \( "${TCL_MAJOR_VERSION}" -gt 8 \) -o \( "${TCL_MAJOR_VERSION}" -eq 8 -a "${TCL_MINOR_VERSION}" -ge 4 \); then
    AC_MSG_RESULT(yes)
else
    AC_MSG_ERROR([setools requires Tcl 8.4 or greater])
fi
TEA_PATH_TKCONFIG
TEA_LOAD_TKCONFIG
AC_MSG_CHECKING([for Tk 8.4 or greater])
if test \( "${TK_MAJOR_VERSION}" -gt 8 \) -o \( "${TK_MAJOR_VERSION}" -eq 8 -a "${TK_MINOR_VERSION}" -ge 4 \); then
    AC_MSG_RESULT(yes)
else
    AC_MSG_ERROR([setools requires Tk 8.4 or greater])
fi
TEA_PUBLIC_TCL_HEADERS
TEA_PUBLIC_TK_HEADERS

AC_ARG_ENABLE(bwidget-check, [  --disable-bwidget-check do not check for BWidget 1.8, assume it exists], enable_bwidget="$enableval", enable_bwidget="yes", enable_bwidget="no")
if test "x${enable_bwidget}" = "xyes"; then
    TEA_PROG_TCLSH
    AC_MSG_CHECKING([for BWidget 1.7 or greater])
    changequote(<<<,>>>)dnl
    cat > ./conftest.tcl <<EOF
if {[catch {package require Tk}]} {
   puts stderr "Could not load Tk."
   exit 1
}
if {![catch {package require BWidget} bwidget_version]} {
    if {[package vcompare \$bwidget_version 1.8] >= 0} {
        exit 0
    } elseif {[package vcompare \$bwidget_version 1.7] >= 0} {
        exit 17
    }
}
exit 16
EOF
    changequote([,])dnl
    ${TCLSH_PROG} ./conftest.tcl
    case $? in
       0)
            AC_MSG_RESULT([1.8+])
            copy_bwidget=no
            bwidget_ver=1.8
            ;;
       1)
            AC_MSG_ERROR([failed; try using --disable-bwidget-check flag])
            ;;
       17)
            AC_MSG_RESULT([1.7])
            copy_bwidget=no
            bwidget_ver=1.7
            ;;
       *)
            AC_MSG_WARN([not found, using setools's BWidget instead])
            copy_bwidget=yes
            bwidget_ver=1.7
            ;;
    esac
    if test ${copy_bwidget} = yes; then
        echo "puts \$tcl_library" > ./conftest.tcl
        BWIDGET_DESTDIR=`${TCLSH_PROG} ./conftest.tcl`
        AC_SUBST(BWIDGET_DESTDIR)
    fi
else
    copy_bwidget=no
    bwidget_ver=1.8
fi

dnl ** look for selinuxfs mount point

AC_ARG_ENABLE(selinux-check, [  --disable-selinux-check do not check for running SELinux, assume it is there], enable_selinux_check="$enableval", enable_selinux_check="yes")
if test "x${enable_selinux_check}" = "xyes"; then
  AC_MSG_CHECKING([for running SELinux system])
  if test ! -r "/selinux/policyvers" ; then
      AC_MSG_WARN([could not read /selinux/policyvers - disabling runtime SELinux support])
      use_selinux=no
  else
      AC_MSG_RESULT(yes)
      use_selinux=yes
  fi
else
      use_selinux=yes
fi


if test ${use_selinux} = "yes"; then
   dnl ** find libselinux and libsepol

   AC_ARG_WITH(sepol-devel, [  --with-sepol-devel      prefix where sepol development files are installed], sepol_devel="$withval", sepol_devel="/usr")
   AC_ARG_WITH(selinux-devel, [  --with-selinux-devel    prefix where SELinux development files are installed], selinux_devel="$withval", selinux_devel="/usr")
   sepol_devel_incdir="${sepol_devel}/include"
   sepol_devel_libdir="${sepol_devel}/lib"
   selinux_devel_incdir="${selinux_devel}/include"
   selinux_devel_libdir="${selinux_devel}/lib"
   CFLAGS="$CFLAGS -I${sepol_devel_incdir} -I${selinux_devel_incdir}"
   LDFLAGS="$LDFLAGS -L${sepol_devel_libdir} -L${selinux_devel_libdir}"
   AC_MSG_CHECKING([for sepol/sepol.h])
   AC_TRY_RUN([#include <sepol/sepol.h>
   #include <stdlib.h>
   int main(void) { exit(0); }],
       AC_MSG_RESULT(yes),
       AC_MSG_ERROR([could not find sepol headers - make sure libsepol-devel is installed]))
   AC_CHECK_LIB(sepol,sepol_policydb_read,,
                AC_MSG_ERROR([could not find libsepol - make sure it is installed]))
   AC_MSG_CHECKING([for selinux/selinux.h])
   AC_TRY_RUN([#include <selinux/selinux.h>
   #include <stdlib.h>
   int main(void) { exit(0); }],
       AC_MSG_RESULT(yes),
       AC_MSG_ERROR([could not find selinux headers - make sure libselinux-devel is installed]))
   AC_CHECK_LIB(selinux, selinux_policy_root,,
        AC_MSG_ERROR([could not find libselinux - make sure it is installed]),
        -lsepol)
fi

AC_ARG_ENABLE(sefs, [  --enable-sefs           allow file system analyses (default)
                          (requires SELinux development files)], sefs="$enableval", sefs="yes")
AC_MSG_CHECKING([for file system analyses])
if test "x${sefs}" = "xyes" ; then
   if test ${use_selinux} = no; then
      AC_MSG_ERROR([sefs requires a running SELinux system])
   fi
   use_sefs=yes
   AC_MSG_RESULT(yes)
else
   use_sefs=no
   AC_MSG_RESULT(disabled)
fi

AC_ARG_ENABLE(sepol-src, [  --enable-sepol-src=PATH use another sepol source tree at PATH
                          (developer only flag)], sepol_srcdir="$enableval", sepol_srcdir="")
if test "x${sepol_srcdir}" = "x"; then
   sepol_srcdir='${top_srcdir}/libqpol'
else
   AC_MSG_CHECKING([for sepol source tree])
   sepol_src_save_CFLAGS=${CFLAGS}
   CFLAGS="$CFLAGS -I${sepol_srcdir}/include -lsepol"
   AC_TRY_RUN([#include <sepol/policydb/policydb.h>
#include <stdlib.h>
   int main(void) { exit(0); }],,
       AC_MSG_ERROR([could not find sepol source tree]))
   CFLAGS="${sepol_src_save_CFLAGS}"
   if test ! -f "${sepol_srcdir}/src/libsepol.a"; then
      AC_MSG_ERROR([could not find precompiled libsepol.a])
   fi
   AC_MSG_RESULT(yes)
fi

if test ${use_selinux} = "yes"; then
dnl Locate selinux policy root directory
    AC_MSG_CHECKING([for selinux policy root])
    changequote(<<<,>>>)dnl
    cat > ./conftest.c <<EOF
#include <stdlib.h>
#include <stdio.h>
#include <selinux/selinux.h>
int
main ()
{
  const char *selinux_dir = selinux_policy_root();
  fputs(selinux_dir, stdout);
  return 0;
}
EOF
    changequote([,])dnl
    CFLAGS="$CFLAGS -I${sepol_devel_incdir} -I${selinux_devel_incdir}"
    LDFLAGS="$LDFLAGS -L${sepol_devel_libdir} -L${selinux_devel_libdir} -lselinux -lsepol"
    gcc ${CFLAGS} ${LDFLAGS} -o conftest conftest.c >&5
    selinux_policy_dir=`./conftest`
    AC_MSG_RESULT(${selinux_policy_dir})
fi

dnl check for policy source
if test ${use_selinux} = "yes"; then
   AC_ARG_WITH(default-policy,
                [  --with-default-policy   path to default policy file],
                selinux_default_policy="$withval",
                selinux_default_policy="${selinux_policy_dir}/src/policy/policy.conf")
   AC_MSG_CHECKING([for policy source])
   if test ! -r "${selinux_default_policy}" ; then
      AC_MSG_WARN([could not read default policy ${selinux_default_policy}])
   else
      AC_MSG_RESULT(${selinux_default_policy})
   fi
fi

dnl check for pkg-config
AC_CHECK_PROG(pkg_config_dir, pkg-config, yes, no)
if test ${pkg_config_dir} = "no"; then
   AC_MSG_ERROR([pkg-config not found])
fi

dnl check for GTK
AC_MSG_CHECKING([for GTK])
GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
if test -z "${GTK_CFLAGS}"; then
   AC_MSG_ERROR([could not find GTK headers])
fi
GTK_LIBS=`pkg-config --libs gtk+-2.0`
if test -z "${GTK_LIBS}"; then
   AC_MSG_ERROR([could not find GTK libraries])
fi
AC_MSG_RESULT([yes])
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)

dnl check for libglade
AC_MSG_CHECKING([for libglade])
GLADE_CFLAGS=`pkg-config --cflags libglade-2.0`
if test -z "${GLADE_CFLAGS}"; then
   AC_MSG_ERROR([could not find libglade headers])
fi
GLADE_LIBS=`pkg-config --libs libglade-2.0`
if test -z "${GLADE_LIBS}"; then
   AC_MSG_ERROR([could not find libglade libraries])
fi
AC_MSG_RESULT([yes])
AC_SUBST(GLADE_CFLAGS)
AC_SUBST(GLADE_LIBS)

dnl check for libxml
AC_MSG_CHECKING([for libxml])
XML_CFLAGS=`pkg-config --cflags libxml-2.0`
if test -z "${XML_CFLAGS}"; then
   AC_MSG_ERROR([could not find libxml headers])
fi
XML_LIBS=`pkg-config --libs libxml-2.0`
if test -z "${XML_LIBS}"; then
   AC_MSG_ERROR([could not find libxml libraries])
fi
AC_MSG_RESULT([yes])
AC_SUBST(XML_CFLAGS)
AC_SUBST(XML_LIBS)

dnl  todo:  dynamic, log file, sharedir
dnl MANDIR			= $(PREFIX)/share/man
dnl DEFAULT_LOG_FILE	= /var/log/messages

dnl set up variables here
if test ${use_selinux} = "yes"; then
   AC_DEFINE(LIBSELINUX, 1, [enable libselinux-specific code])
fi

if test ${use_sefs} = "yes"; then
   AC_DEFINE(LIBSEFS, 1, [enable analyses of a SELinux filesystem])
   AC_SUBST(use_sefs)
fi

AM_CONDITIONAL(WANT_LIBSEFS, test ${use_sefs} = "yes")
AM_CONDITIONAL(COPY_BWIDGET, test ${copy_bwidget} = "yes")

apol_install_dir=${datadir}/apol
apol_help_dir=${datadir}/apol
profile_install_dir=${datadir}/sechecker/profiles

AC_SUBST(VERSION)
AC_SUBST(sepol_srcdir)
AC_SUBST(libqpol_version)
AC_SUBST(libqpol_soname)
AC_SUBST(libapol_version)
AC_SUBST(libapol_soname)
AC_SUBST(libapol_tcl_soname)
AC_SUBST(libpoldiff_version)
AC_SUBST(libpoldiff_soname)
AC_SUBST(libsefs_version)
AC_SUBST(libsefs_soname)
AC_SUBST(apol_install_dir)
AC_SUBST(apol_help_dir)
AC_SUBST(selinux_policy_dir)
AC_SUBST(selinux_default_policy)
AC_SUBST(profile_install_dir)

AC_DEFINE_UNQUOTED(LIBAPOL_VERSION_STRING, "${libapol_version}", [libapol version])
AC_DEFINE_UNQUOTED(LIBSEAUDIT_VERSION_STRING, "${libseaudit_version}", [libapol version])

# for older version of BWidget, overcome bug in NoteBook::bindtabs and
# add a new -autopost option to ComboBox
AC_CONFIG_COMMANDS([config.tcl], [[
   if test ${bwidget_ver} = 1.7; then
        cat > ./config.tcl <<EOF
proc tcl_patch_bwidget {} {
    # explicitly pull in old BWidget code before patching
    NoteBook .foo ; destroy .foo
    ComboBox .foo ; destroy .foo
    proc NoteBook::bindtabs { path event script } {
        if { \$script != "" } {
            append script " \\[NoteBook::_get_page_name [list \$path] current 1\\]"
            \$path.c bind "page" \$event \$script
        } else {
            \$path.c bind "page" \$event {}
        }
    }
EOF
        cat ${ac_top_srcdir}/packages/combobox.tcl >> ./config.tcl
        echo "}" >> ./config.tcl
   else
        echo "" > config.tcl
   fi
]], [bwidget_ver=$bwidget_ver])

AC_CONFIG_FILES([Makefile VERSION \
                 libqpol/Makefile libqpol/src/Makefile libqpol/include/Makefile libqpol/include/qpol/Makefile \
                 libapol/Makefile libapol/src/Makefile libapol/include/Makefile libapol/include/apol/Makefile \
                 libapol-tcl/Makefile \
                 libpoldiff/Makefile libpoldiff/src/Makefile libpoldiff/include/Makefile libpoldiff/include/poldiff/Makefile \
                 libsefs/Makefile libsefs/src/Makefile libsefs/include/Makefile libsefs/include/sefs/Makefile \
		 libseaudit/Makefile \
                 secmds/Makefile \
                 apol/Makefile \
                 awish/Makefile \
                 sechecker/Makefile \
		 seaudit/Makefile \
                 packages/Makefile])

AC_OUTPUT

echo "*** Configuration complete.  Do \`make help' to get a list of setools targets."
