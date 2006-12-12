AC_INIT(setools, 3.1, [Tresys Technology <setools@tresys.com>], [setools])
AC_CONFIG_SRCDIR(awish/awish.c)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(setools, 3.1)

dnl *** update these variables as versions change; also update AC_INIT ***
libqpol_version=2.0
libqpol_soname=libqpol.so.2

libapol_version=3.1
libapol_soname=libapol.so.3.1
libapol_tcl_soname=libapol-tcl.so.3.1

libpoldiff_version=1.1
libpoldiff_soname=libpoldiff.so.1.1

libsefs_version=3.1
libsefs_soname=libsefs.so.3.1

libseaudit_version=4.0.0
libseaudit_soname=libseaudit.so.4

setoolsdir='${prefix}/share/setools-3.1'

version_min_sepol_major=1
version_min_sepol_minor=12
version_min_sepol_patch=27

dnl *** end of tunable values ***

AC_GNU_SOURCE
AC_PROG_CC
AC_LANG_C
AC_HEADER_STDC
AC_PROG_RANLIB
AC_PROG_LN_S
AM_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_CHECK_SIZEOF(char *)
AC_C_BIGENDIAN
AC_CHECK_FUNCS(rand_r)

AC_ARG_ENABLE(shared,
              AC_HELP_STRING([--enable-shared],
                             [link against shared libapol (default)]),
              enable_shared="$enableval",
              enable_shared="yes")
AC_MSG_CHECKING([for how to link against libraries])
if test "x${enable_shared}" = xyes; then
    use_shared=yes
    AC_MSG_RESULT(shared)
else
    use_shared=no
    AC_MSG_RESULT(static)
fi

AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug],
                             [compile with full debugging support]),
              enable_debug="$enableval")
AC_MSG_CHECKING([for debugging support])
if test "x${enable_debug}" = xyes; then
    DEBUGCFLAGS="-g3 -gdwarf-2 -O0 -Wall -DSETOOLS_DEBUG=1"
    DEBUGLDFLAGS="-g"
    QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so -Wl,-rpath=$(top_builddir)/libqpol/src'
    APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.a -Wl,-rpath=$(top_builddir)/libapol/src'
    SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.a -Wl,-rpath=$(top_builddir)/libsefs/src'
    POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.a -Wl,-rpath=$(top_builddir)/libpoldiff/src'
    SEAUDIT_LIB_FLAG='$(top_builddir)/libseaudit/src/libseaudit.a -Wl,-rpath=$(top_builddir)/libseaudit/src'
    AC_MSG_RESULT(yes)
else
    AC_DEFINE(NDEBUG, 1, [disable calls to assert()])
    DEBUGCFLAGS="-fno-strict-aliasing"
    DEBUGLDFLAGS=""
    if test ${use_shared} = yes; then
        QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so'
        APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.so'
        SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.so'
        POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.so'
        SEAUDIT_LIB_FLAG='$(top_builddir)/libseaudit/src/libseaudit.so'
    else
        QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so'
        APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.a'
        SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.a'
        POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.a'
        SEAUDIT_LIB_FLAG='$(top_builddir)/libseaudit/src/libseaudit.a'
    fi
    AC_MSG_RESULT(disabled)
fi
AC_SUBST(DEBUGCFLAGS)
AC_SUBST(DEBUGLDFLAGS)
QPOL_CFLAGS='-I$(top_srcdir)/libqpol/include'
APOL_CFLAGS='-I$(top_srcdir)/libapol/include'
SEFS_CFLAGS='-I$(top_srcdir)/libsefs/include'
POLDIFF_CFLAGS='-I$(top_srcdir)/libpoldiff/include'
SEAUDIT_CFLAGS='-I$(top_srcdir)/libseaudit/include'
AC_SUBST(QPOL_CFLAGS)
AC_SUBST(APOL_CFLAGS)
AC_SUBST(SEFS_CFLAGS)
AC_SUBST(POLDIFF_CFLAGS)
AC_SUBST(SEAUDIT_CFLAGS)
AC_SUBST(QPOL_LIB_FLAG)
AC_SUBST(APOL_LIB_FLAG)
AC_SUBST(SEFS_LIB_FLAG)
AC_SUBST(POLDIFF_LIB_FLAG)
AC_SUBST(SEAUDIT_LIB_FLAG)

AC_ARG_ENABLE(warnall,
              AC_HELP_STRING([--enable-warnall],
                             [compile with most warnings enabled]),
              enable_warnall="$enableval")
if test "x${enable_warnall}" = xyes; then
    WARNCFLAGS=" -O1 -Wall -Wshadow -Wundef -pedantic-errors -Wuninitialized -fno-strict-aliasing -std=c99"
    WARNLDFLAGS=""
else
    WARNCFLAGS=""
    WARNLDFLAGS=""
fi
AC_SUBST(WARNCFLAGS)
AC_SUBST(WARNLDFLAGS)

AC_ARG_ENABLE(profiling,
              AC_HELP_STRING([--enable-profiling],
                             [compile with gcov and gprof profiling support]),
              enable_profiling="$enableval")
AC_MSG_CHECKING([for profiling support])
if test "x${enable_profiling}" = xyes; then
    PROFILECFLAGS="-ftest-coverage -fprofile-arcs -pg"
    PROFILELDFLAGS="-lgcov"
    AC_MSG_RESULT(yes)
else
    PROFILECFLAGS=""
    PROFILELDFLAGS=""
    AC_MSG_RESULT(disabled)
fi
AC_SUBST(PROFILECFLAGS)
AC_SUBST(PROFILELDFLAGS)

AC_ARG_ENABLE(gui,
              AC_HELP_STRING([--disable-gui],
                             [do not compile graphical tools (default is ENABLE)]),
              build_gui="$enableval",
              build_gui="yes")
AC_MSG_CHECKING([which setools programs to build])
if test "x${build_gui}" = "xyes"; then
    AC_MSG_RESULT(all)
else
    AC_MSG_RESULT(only command line tools)
fi

if test "x${build_gui}" = "xyes"; then
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
fi

AC_ARG_ENABLE(bwidget-check,
              AC_HELP_STRING([--disable-bwidget-check],
                             [do not check for BWidget 1.8, assume it exists]),
              enable_bwidget="$enableval",
              enable_bwidget="yes")
if test "x${enable_gui}" = "xno"; then
    enable_bwidget=no
fi
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
            AC_MSG_ERROR([failed.  Try using --disable-bwidget-check flag if compiling in a non-graphical environment.])
            ;;
       17)
            AC_MSG_RESULT([1.7])
            copy_bwidget=no
            bwidget_ver=1.7
            ;;
       *)
            AC_MSG_WARN([not found, using setools's BWidget 1.8 instead])
            copy_bwidget=yes
            bwidget_ver=1.8
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

AC_ARG_ENABLE(selinux-check,
              AC_HELP_STRING([--disable-selinux-check],
                             [do not check for running SELinux, assume it is there]),
              enable_selinux_check="$enableval",
              enable_selinux_check="yes")
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

dnl ** find libselinux and libsepol

AC_ARG_WITH(sepol-devel,
            AC_HELP_STRING([--with-sepol-devel],
                           [prefix where sepol development files are installed]),
            sepol_devel="$withval",
            sepol_devel="/usr")
AC_ARG_WITH(selinux-devel,
            AC_HELP_STRING([--with-selinux-devel],
                           [prefix where SELinux development files are installed]),
            selinux_devel="$withval",
            selinux_devel="/usr")
sepol_devel_incdir="${sepol_devel}/include"
sepol_devel_libdir="${sepol_devel}/lib"
selinux_devel_incdir="${selinux_devel}/include"
selinux_devel_libdir="${selinux_devel}/lib"
AC_MSG_CHECKING([for sepol/sepol.h])
selinux_save_CFLAGS="${CFLAGS}"
SELINUX_LIB_FLAG="-L${sepol_devel_libdir} -L${selinux_devel_libdir}"
CFLAGS="-I${sepol_devel_incdir} -I${selinux_devel_incdir} ${SELINUX_LIB_FLAG} ${CFLAGS}"
AC_TRY_RUN([#include <sepol/sepol.h>
            #include <stdlib.h>
            int main(void) { exit(0); }],
           AC_MSG_RESULT(yes),
           AC_MSG_ERROR([could not find sepol headers at $sepol_devel_incdir - make sure libsepol-devel is installed]))
AC_CHECK_LIB(sepol,sepol_policydb_read,,
             AC_MSG_ERROR([could not find libsepol at $sepol_devel_libdir]))
AC_MSG_CHECKING([for selinux/selinux.h])
AC_TRY_RUN([#include <selinux/selinux.h>
            #include <stdlib.h>
            int main(void) { exit(0); }],
           AC_MSG_RESULT(yes),
           AC_MSG_ERROR([could not find selinux headers at $selinux_devel_incdir - make sure libselinux-devel is installed]))
AC_CHECK_LIB(selinux, selinux_policy_root,,
AC_MSG_ERROR([could not find libselinux at $selinux_devel_libdir]),
             -lsepol)
CFLAGS="${selinux_save_CFLAGS}"

AC_ARG_ENABLE(sefs,
              AC_HELP_STRING([--disable-sefs],
                             [disallow file system analyses (requires SELinux development files) (default is ENABLE)]),
              sefs="$enableval",
              sefs="yes")
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

AC_ARG_ENABLE(sepol-src,
              AC_HELP_STRING([--enable-sepol-src=PATH],
                             [use another sepol source tree at PATH (developer only flag)]),
              sepol_srcdir="$enableval",
              sepol_srcdir="")
if test "x${sepol_srcdir}" = "x"; then
   sepol_srcdir=${sepol_devel_libdir}
else
   AC_MSG_CHECKING([for compatible sepol source tree])
   sepol_version=${sepol_srcdir}/VERSION
   if test ! -r $sepol_version; then
      AC_MSG_ERROR([could not read $sepol_version])
   fi
   version_sepol_major=$(cut -d. -f1 < ${sepol_version})
   version_sepol_minor=$(cut -d. -f2 < ${sepol_version})
   version_sepol_patch=$(cut -d. -f3 < ${sepol_version})
   version_ok=""
   if test $version_sepol_major -gt $version_min_sepol_major; then
      version_ok=1
   elif test $version_sepol_major -eq $version_min_sepol_major -a \
             $version_sepol_minor -gt $version_min_sepol_minor; then
      version_ok=1
   elif test $version_sepol_major -eq $version_min_sepol_major -a \
             $version_sepol_minor -eq $version_min_sepol_minor -a \
             $version_sepol_patch -ge $version_min_sepol_patch; then
      version_ok=1
   fi
   if test -z $version_ok; then
      version_min_sepol="${version_min_sepol_major}.${version_min_sepol_minor}.${version_min_sepol_patch}"
      version_found_sepol="${version_sepol_major}.${version_sepol_minor}.${version_sepol_patch}"
      AC_MSG_ERROR([setools requires sepol version $version_min_sepol or greater (found $version_found_sepol)])
   fi
   sepol_srcdir="${sepol_srcdir}/src"
   sepol_src_save_CFLAGS="${CFLAGS}"
   CFLAGS="${CFLAGS} -I${sepol_srcdir}/../include ${SELINUX_LIB_FLAG}"
   AC_TRY_RUN([#include <sepol/policydb/policydb.h>
#include <stdlib.h>
   int main(void) { exit(0); }],,
       AC_MSG_ERROR([could not find sepol source tree]))
   CFLAGS="${sepol_src_save_CFLAGS}"
   if test ! -f "${sepol_srcdir}/libsepol.a"; then
      AC_MSG_ERROR([could not find precompiled libsepol.a])
   fi
   sepol_devel_incdir="${sepol_srcdir}/../include"
   AC_MSG_RESULT(yes)
fi
SELINUX_CFLAGS="-I${sepol_devel_incdir} -I${selinux_devel_incdir}"
AC_SUBST(SELINUX_CFLAGS)
AC_SUBST(SELINUX_LIB_FLAG)

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
    selinux_save_CFLAGS="${CFLAGS}"
    CFLAGS="${SELINUX_CFLAGS} ${SELINUX_LIB_FLAG} -lselinux -lsepol ${CFLAGS}"
    gcc ${CFLAGS} -o conftest conftest.c >&5
    selinux_policy_dir=`./conftest`
    AC_MSG_RESULT(${selinux_policy_dir})
    CFLAGS="${selinux_save_CFLAGS}"
fi

dnl check for policy source
if test ${use_selinux} = "yes"; then
   AC_ARG_WITH(default-policy,
               AC_HELP_STRING([--with-default-policy],
                              [path to default policy file]),
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

if test "x${build_gui}" = xyes; then
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

  dnl check for gdk-pixbuf
  AC_MSG_CHECKING([for gdk-pixbuf])
  PIXBUF_CFLAGS=`pkg-config --cflags gdk-pixbuf-2.0`
  if test -z "${PIXBUF_CFLAGS}"; then
     AC_MSG_ERROR([could not find libgdk-pixbuf headers])
  fi
  PIXBUF_LIBS=`pkg-config --libs gdk-pixbuf-2.0`
  if test -z "${PIXBUF_LIBS}"; then
     AC_MSG_ERROR([could not find libgdk-pixbuf libraries])
  fi
  AC_MSG_RESULT([yes])
  AC_SUBST(PIXBUF_CFLAGS)
  AC_SUBST(PIXBUF_LIBS)

  dnl check for gthread
  AC_MSG_CHECKING([for gthread])
  GTHREAD_CFLAGS=`pkg-config --cflags gthread-2.0`
  if test -z "${GTHREAD_CFLAGS}"; then
     AC_MSG_ERROR([could not find gthread headers])
  fi
  GTHREAD_LIBS=`pkg-config --libs gthread-2.0`
  if test -z "${GTHREAD_LIBS}"; then
     AC_MSG_ERROR([could not find gthread libraries])
  fi
  AC_MSG_RESULT([yes])
  AC_SUBST(GTHREAD_CFLAGS)
  AC_SUBST(GTHREAD_LIBS)
fi

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
AM_CONDITIONAL(BUILD_GUI, test ${build_gui} = "yes")

profile_install_dir='${setoolsdir}/sechecker-profiles'

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
AC_SUBST(libseaudit_version)
AC_SUBST(libseaudit_soname)
AC_SUBST(setoolsdir)
AC_SUBST(selinux_policy_dir)
AC_SUBST(selinux_default_policy)
AC_SUBST(profile_install_dir)

AC_DEFINE_UNQUOTED(LIBAPOL_VERSION_STRING, "${libapol_version}", [libapol version])
AC_DEFINE_UNQUOTED(LIBQPOL_VERSION_STRING, "${libqpol_version}", [libqpol version])
AC_DEFINE_UNQUOTED(LIBPOLDIFF_VERSION_STRING, "${libpoldiff_version}", [libpoldiff version])
AC_DEFINE_UNQUOTED(LIBSEFS_VERSION_STRING, "${libsefs_version}", [libsefs version])
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
    MainFrame .foo ; destroy .foo
EOF
        cat ${ac_top_srcdir}/packages/combobox.tcl >> ./config.tcl
	cat ${ac_top_srcdir}/packages/mainframe.tcl >> ./config.tcl
	cat ${ac_top_srcdir}/packages/notebook.tcl >> ./config.tcl
        echo "}" >> ./config.tcl
   else
        echo "" > ./config.tcl
   fi
   if test "x${enable_debug}" = xyes; then
        cat >> ./config.tcl <<EOF
namespace eval ::tkcon {
    variable OPT
    variable PRIV
    set PRIV(showOnStartup) 0
    set PRIV(root) .console
    set PRIV(protocol) {tkcon hide}
    set OPT(exec) ""
}
if {![catch {source tkcon.tcl}]} {
    package require tkcon
    bind . <F8> {tkcon show}
}
EOF
   fi
]], [bwidget_ver=$bwidget_ver; enable_debug=$enable_debug])

AC_CONFIG_FILES([Makefile VERSION \
                 libqpol/Makefile libqpol/src/Makefile libqpol/include/Makefile libqpol/include/qpol/Makefile \
                 libapol/Makefile libapol/src/Makefile libapol/include/Makefile libapol/include/apol/Makefile \
                 libapol-tcl/Makefile \
                 libpoldiff/Makefile libpoldiff/src/Makefile libpoldiff/include/Makefile libpoldiff/include/poldiff/Makefile \
                 libsefs/Makefile libsefs/src/Makefile libsefs/include/Makefile libsefs/include/sefs/Makefile \
                 libseaudit/Makefile libseaudit/src/Makefile libseaudit/include/Makefile libseaudit/include/seaudit/Makefile \
                 secmds/Makefile \
                 apol/Makefile \
                 awish/Makefile \
                 sechecker/Makefile \
                 seaudit/Makefile \
                 sediff/Makefile \
                 man/Makefile \
                 packages/Makefile])

AC_OUTPUT

echo "*** Configuration complete.  Do \`make help' to get a list of setools targets."
