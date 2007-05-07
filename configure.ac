AC_INIT(setools, 3.3, [Tresys Technology <setools@tresys.com>], [setools])
AC_CONFIG_SRCDIR(libqpol/src/policy.c)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([-Wno-portability])

dnl *** update these variables as versions change; also update AC_INIT ***
libqpol_version=1.3
libqpol_soname=libqpol.so.1
libqpol_pyswig_soname=_qpol.so.1
libqpol_jswig_soname=libjqpol.so.1
libqpol_tswig_soname=libtqpol.so.1

libapol_version=4.1
libapol_soname=libapol.so.4
libapol_pyswig_soname=_apol.so.4
libapol_jswig_soname=libjapol.so.4
libapol_tswig_soname=libtapol.so.4

libpoldiff_version=1.2
libpoldiff_soname=libpoldiff.so.1
libpoldiff_pyswig_soname=_poldiff.so.1
libpoldiff_jswig_soname=libjpoldiff.so.1
libpoldiff_tswig_soname=libtpoldiff.so.1

libsefs_version=3.1
libsefs_soname=libsefs.so.3
dnl libsefs will not be swigified

libseaudit_version=4.1
libseaudit_soname=libseaudit.so.4
libseaudit_pyswig_soname=_seaudit.so.4
libseaudit_jswig_soname=libjseaudit.so.4
libseaudit_tswig_soname=libtseaudit.so.4

setoolsdir='${prefix}/share/setools-3.3'

version_min_sepol_major=1
version_min_sepol_minor=12
version_min_sepol_patch=27

dnl *** end of tunable values ***

AC_GNU_SOURCE
AC_PROG_CC
AC_LANG([C])
AC_HEADER_STDC
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_CHECK_SIZEOF(char *)
AC_C_BIGENDIAN
AC_CHECK_FUNCS(rand_r)

AC_CACHE_SAVE

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
    DEBUGJFLAGS="-g"
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
    DEBUGJFLAGS=""
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
AC_SUBST(DEBUGJFLAGS)
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
    WARNJFLAGS=" -verbose"
    WARNLDFLAGS=""
else
    WARNCFLAGS=""
    WARNJFLAGS=""
    WARNLDFLAGS=""
fi
AC_SUBST(WARNCFLAGS)
AC_SUBST(WARNJFLAGS)
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

do_swigify=no
do_swigify_java=no
do_swigify_python=no
AC_ARG_ENABLE(swig-java,
              AC_HELP_STRING([--enable-swig-java],
                             [build SWIG interfaces for Java]),
              enable_jswig="$enableval")
if test "x${enable_jswig}" = xyes; then
   if test ${do_swigify} = no; then
      AC_PROG_SWIG(1.3.28)
   fi
   AC_JAVA_OPTIONS
   if test "x$JAVAPREFIX" = x; then
      JAVAPREFIX=/usr/lib/jvm/java-gcj
   fi
   AC_CHECK_CLASSPATH
   AC_PROG_JAVAC
   AC_PROG_JAVA
   AC_PROG_JAR
   SWIG_JAVA_OPT=-java
   java_save_CFLAGS="${CFLAGS}"
   SWIG_JAVA_CFLAGS="-I${JAVAPREFIX}/include -I${JAVAPREFIX}/include/linux -DSWIGJAVA=1"
   CFLAGS="${CFLAGS} ${SWIG_JAVA_CFLAGS}"
   AC_CHECK_HEADER([jni.h], , AC_MSG_ERROR([Not found.  Specify a Java SDK with --with-java-prefix flag.]))
   AC_CHECK_HEADER([jni_md.h], , AC_MSG_ERROR([Not found.  Specify a Java SDK with --with-java-prefix flag.]))
   CFLAGS="${java_save_CFLAGS}"
   AC_SUBST(SWIG_JAVA_OPT)
   AC_SUBST(SWIG_JAVA_CFLAGS)
   do_swigify_java=yes
   do_swigify=yes
fi
AC_ARG_ENABLE(swig-python,
              AC_HELP_STRING([--enable-swig-python],
                             [build SWIG interfaces for Python]),
              enable_pyswig="$enableval")
if test "x${enable_pyswig}" = xyes; then
   if test ${do_swigify} = no; then
      AC_PROG_SWIG(1.3.28)
   fi
   AM_PATH_PYTHON(2.3)
   SWIG_PYTHON
   do_swigify_python=yes
   do_swigify=yes
fi
if test ${do_swigify} = "yes"; then
   AC_PROG_SWIG(1.3.28)
fi
build_apol=yes
AC_ARG_ENABLE(swig-tcl,
              AC_HELP_STRING([--enable-swig-tcl],
                             [build SWIG interfaces for Tcl (default)]),
              enable_tclswig="$enableval", enable_tclswig="yes")
if test "x${enable_tclswig}" = xyes; then
   if test ${do_swigify} = no; then
      AC_PROG_SWIG(1.3.28)
   fi
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
   TEA_PROG_TCLSH
   SWIG_TCL_OPT=-tcl
   SWIG_TCL_CFLAGS="${TCL_INCLUDES} -DSWIGTCL=1"
   AC_SUBST(SWIG_TCL_OPT)
   AC_SUBST(SWIG_TCL_CFLAGS)
   do_swigify_tcl=yes
   do_swigify=yes
else
   build_apol=no
fi
AC_CACHE_SAVE

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
    build_apol=no
fi

if test "x${enable_debug}" = xyes; then
   TCL_AUTOPATH='$(top_builddir)/libqpol/swig/tcl $(top_builddir)/libapol/swig/tcl $(top_builddir)/libapol-tcl'
else
   TCL_AUTOPATH='$(libdir)/setools'
fi
AC_SUBST(TCL_AUTOPATH)

AC_ARG_ENABLE(bwidget-check,
              AC_HELP_STRING([--disable-bwidget-check],
                             [do not check for BWidget 1.8, assume it exists]),
              enable_bwidget="$enableval",
              enable_bwidget="yes")
if test ${build_apol} = "no"; then
    enable_bwidget=no
fi
if test "x${enable_bwidget}" = "xyes"; then
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

AC_CACHE_SAVE

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
selinux_devel_incdir="${selinux_devel}/include"
dnl if /lib64 exists then use that directory, otherwise revert to just /lib
for dir in lib64 lib ; do
  sepol_devel_libdir="${sepol_devel}/${dir}"
  if test -d ${sepol_devel_libdir} ; then
    break
  fi
done
for dir in lib64 lib ; do
  selinux_devel_libdir="${selinux_devel}/${dir}"
  if test -d ${selinux_devel_libdir} ; then
    break
  fi
done
AC_MSG_CHECKING([for sepol/sepol.h])
selinux_save_CFLAGS="${CFLAGS}"
selinux_save_CPPFLAGS="${CPPFLAGS}"
CFLAGS="${CFLAGS} -I${sepol_devel_incdir} -I${selinux_devel_incdir}"
CPPFLAGS="${CPPFLAGS} -I${sepol_devel_incdir} -I${selinux_devel_incdir}"
AC_CHECK_HEADER([sepol/sepol.h], , AC_MSG_ERROR([could not find sepol headers at $sepol_devel_incdir - make sure libsepol-devel is installed]))
AC_CHECK_LIB([sepol], [sepol_policydb_read], ,
             AC_MSG_ERROR([could not find libsepol at $sepol_devel_libdir]))
AC_CHECK_HEADER([selinux/selinux.h], , AC_MSG_ERROR([could not find selinux headers at $selinux_devel_incdir - make sure libselinux-devel is installed]))
AC_CHECK_LIB([selinux], [selinux_policy_root], ,
AC_MSG_ERROR([could not find libselinux at $selinux_devel_libdir]),
             -lsepol)
SELINUX_LIB_FLAG="-L${sepol_devel_libdir} -L${selinux_devel_libdir}"
CFLAGS="${selinux_save_CFLAGS}"
CPPFLAGS="${selinux_save_CPPFLAGS}"

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
   AC_MSG_RESULT([yes])
   sepol_srcdir="${sepol_srcdir}/src"
   sepol_src_save_CFLAGS="${CFLAGS}"
   sepol_src_save_CPPFLAGS="${CPPFLAGS}"
   CFLAGS="${CFLAGS} -I${sepol_srcdir}/../include"
   CPPFLAGS="${CPPFLAGS} -I${sepol_srcdir}/../include"
   AC_CHECK_HEADER([sepol/policydb/policydb.h], , AC_MSG_ERROR([could not find sepol source tree]))
   CFLAGS="${sepol_src_save_CFLAGS}"
   CPPFLAGS="${sepol_src_save_CPPFLAGS}"
   if test ! -f "${sepol_srcdir}/libsepol.a"; then
      AC_MSG_ERROR([could not find precompiled libsepol.a])
   fi
   sepol_devel_incdir="${sepol_srcdir}/../include"
fi
SELINUX_CFLAGS="-I${sepol_devel_incdir} -I${selinux_devel_incdir}"
AC_SUBST(SELINUX_CFLAGS)
AC_SUBST(SELINUX_LIB_FLAG)

sepol_save_CFLAGS="${CFLAGS}"
sepol_save_CPPFLAGS="${CPPFLAGS}"
CFLAGS="${CFLAGS} ${SELINUX_CFLAGS} ${SELINUX_LIB_FLAG}"
CPPFLAGS="${CPPFLAGS} ${SELINUX_CFLAGS}"
dnl if using libsepol < 2.0.0, then map the old error codes to the new
dnl format
AC_CHECK_HEADER([sepol/errcodes.h], sepol_new_defines="yes", sepol_new_defines="no")

dnl check for broken boolmap behavior in libsepol version 2.0.2
AC_CHECK_DECL([cond_node_create], sepol_check_boolmap="yes", sepol_check_boolmap="no", [#include <sepol/policydb/conditional.h>])
if test ${sepol_check_boolmap} = "yes"; then
    dnl check for boolmap parameter that is fixed in version 2.0.3
    AC_MSG_CHECKING([correct libsepol expand behavior])
    AC_COMPILE_IFELSE(
        [AC_LANG_SOURCE([
#include <sepol/policydb/expand.h>
int main () {
  return expand_module_avrules(NULL, NULL, NULL, NULL, NULL, 0, 0);
}])],
    AC_MSG_RESULT([yes]),
    AC_MSG_ERROR([this version of libsepol is incompatible with SETools]))
  sepol_new_expand_boolmap="yes"
else
  sepol_new_expand_boolmap="no"
fi

AC_RUN_IFELSE(
   [AC_LANG_SOURCE([
#include <sepol/policydb/policydb.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    FILE *f = fopen("conftest.data", "w");
    if (f != NULL && fprintf(f, "%d", POLICYDB_VERSION_MAX) > 0) {
       fclose(f);
       exit(EXIT_SUCCESS);
    }
    exit(EXIT_FAILURE);
}])],
    sepol_policy_version_max=`cat conftest.data`,
    AC_MSG_FAILURE([could not determine maximum libsepol policy version]))
AC_DEFINE_UNQUOTED(SEPOL_POLICY_VERSION_MAX, ${sepol_policy_version_max}, [maximum policy version supported by libsepol])
CFLAGS="${sepol_save_CFLAGS}"
CPPFLAGS="${sepol_save_CPPFLAGS}"

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

AC_CACHE_SAVE

dnl check for pkg-config
AC_CHECK_PROG(has_pkg_config, pkg-config, yes, no)
if test ${has_pkg_config} = "no"; then
   AC_MSG_ERROR([pkg-config not found])
fi

if test "x${build_gui}" = xyes; then
  dnl check for GTK+
  AC_MSG_CHECKING([for GTK])
  pkg-config --exists 'gtk+-2.0 >= 2.8'
  if test $? -ne 0; then
     AC_MSG_ERROR([setools requires GTK+ 2.8 or greater])
  fi
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

AM_CONDITIONAL(DO_SWIGIFY, test ${do_swigify} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_PYTHON, test ${do_swigify_python} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_JAVA, test ${do_swigify_java} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_TCL, test ${do_swigify_tcl} = "yes")
AM_CONDITIONAL(WANT_LIBSEFS, test ${use_sefs} = "yes")
AM_CONDITIONAL(COPY_BWIDGET, test ${copy_bwidget} = "yes")
AM_CONDITIONAL(BUILD_APOL, test ${build_apol} = "yes")
AM_CONDITIONAL(BUILD_GUI, test ${build_gui} = "yes")

profile_install_dir='${setoolsdir}/sechecker-profiles'

AC_SUBST(VERSION)
AC_SUBST(sepol_srcdir)
AC_SUBST(libqpol_version)
AC_SUBST(libqpol_soname)
AC_SUBST(libqpol_pyswig_soname)
AC_SUBST(libqpol_jswig_soname)
AC_SUBST(libqpol_tswig_soname)
AC_SUBST(libapol_version)
AC_SUBST(libapol_soname)
AC_SUBST(libapol_pyswig_soname)
AC_SUBST(libapol_jswig_soname)
AC_SUBST(libapol_tswig_soname)
AC_SUBST(libpoldiff_version)
AC_SUBST(libpoldiff_soname)
AC_SUBST(libpoldiff_pyswig_soname)
AC_SUBST(libpoldiff_jswig_soname)
AC_SUBST(libpoldiff_tswig_soname)
AC_SUBST(libsefs_version)
AC_SUBST(libsefs_soname)
AC_SUBST(libseaudit_version)
AC_SUBST(libseaudit_soname)
AC_SUBST(libseaudit_pyswig_soname)
AC_SUBST(libseaudit_jswig_soname)
AC_SUBST(libseaudit_tswig_soname)
AC_SUBST(setoolsdir)
AC_SUBST(selinux_policy_dir)
AC_SUBST(selinux_default_policy)
AC_SUBST(profile_install_dir)

AC_DEFINE_UNQUOTED(LIBAPOL_VERSION_STRING, "${libapol_version}", [libapol version])
AC_DEFINE_UNQUOTED(LIBQPOL_VERSION_STRING, "${libqpol_version}", [libqpol version])
AC_DEFINE_UNQUOTED(LIBPOLDIFF_VERSION_STRING, "${libpoldiff_version}", [libpoldiff version])
AC_DEFINE_UNQUOTED(LIBSEFS_VERSION_STRING, "${libsefs_version}", [libsefs version])
AC_DEFINE_UNQUOTED(LIBSEAUDIT_VERSION_STRING, "${libseaudit_version}", [libapol version])
AC_DEFINE(SQLITE_PTR_SZ, SIZEOF_CHAR_P, [size of a pointer, as used by SQLite3])
if test ${sepol_new_defines} != "yes" ; then
   AC_DEFINE(SEPOL_ENOMEM, HASHTAB_OVERFLOW, [remap of libsepol 1.x.x define to 2.x.x])
   AC_DEFINE(SEPOL_EEXIST, HASHTAB_PRESENT, [remap of libsepol 1.x.x define to 2.x.x])
fi

if test ${sepol_new_expand_boolmap} == "yes" ; then
   AC_DEFINE(HAVE_SEPOL_BOOLMAP, 1, [sepol's new expand boolmap behavior])
fi

# For older version of BWidget, overcome bug in NoteBook::bindtabs and
# add a new -autopost option to ComboBox.
AC_CONFIG_COMMANDS([config.tcl], [[
   echo "" > ./config.tcl
   if test ${bwidget_ver} = 1.7; then
        cat >> ./config.tcl <<EOF
proc tcl_config_patch_bwidget {} {
    # explicitly pull in old BWidget code before patching
    NoteBook .foo ; destroy .foo
    ComboBox .foo ; destroy .foo
    MainFrame .foo ; destroy .foo
EOF
        cat ${ac_top_srcdir}/packages/combobox.tcl >> ./config.tcl
	cat ${ac_top_srcdir}/packages/mainframe.tcl >> ./config.tcl
	cat ${ac_top_srcdir}/packages/notebook.tcl >> ./config.tcl
        echo "}" >> ./config.tcl
   fi
   echo "proc tcl_config_init {} {" >> ./config.tcl
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
   echo "}" >> ./config.tcl
   echo "proc tcl_config_get_version {} {" >> ./config.tcl
   echo "    return ${version}" >> ./config.tcl
   echo "}" >> ./config.tcl
   echo "proc tcl_config_use_sefs {} {" >> ./config.tcl
   if test "x${use_sefs}" = "xyes"; then
      echo "    return 1" >> ./config.tcl
   else
      echo "    return 0" >> ./config.tcl
   fi
   echo "}" >> ./config.tcl
]], [bwidget_ver=$bwidget_ver; enable_debug=$enable_debug; version=$VERSION; use_sefs=${use_sefs}])

AC_CONFIG_FILES([Makefile VERSION \
                 libqpol/Makefile libqpol/src/Makefile libqpol/include/Makefile libqpol/include/qpol/Makefile \
                 libqpol/swig/Makefile libqpol/swig/python/Makefile libqpol/swig/java/Makefile libqpol/swig/java/MANIFEST.MF libqpol/swig/tcl/Makefile \
                 libapol/Makefile libapol/src/Makefile libapol/include/Makefile libapol/include/apol/Makefile \
                 libapol/swig/Makefile libapol/swig/python/Makefile libapol/swig/java/Makefile libapol/swig/java/MANIFEST.MF libapol/swig/tcl/Makefile \
                 libapol-tcl/Makefile \
                 libpoldiff/Makefile libpoldiff/src/Makefile libpoldiff/include/Makefile libpoldiff/include/poldiff/Makefile \
                 libpoldiff/swig/Makefile libpoldiff/swig/python/Makefile libpoldiff/swig/java/Makefile libpoldiff/swig/java/MANIFEST.MF libpoldiff/swig/tcl/Makefile \
                 libsefs/Makefile libsefs/src/Makefile libsefs/include/Makefile libsefs/include/sefs/Makefile \
                 libseaudit/Makefile libseaudit/src/Makefile libseaudit/include/Makefile libseaudit/include/seaudit/Makefile \
                 libseaudit/swig/Makefile libseaudit/swig/python/Makefile libseaudit/swig/java/Makefile libseaudit/swig/java/MANIFEST.MF libseaudit/swig/tcl/Makefile \
                 secmds/Makefile \
                 apol/Makefile \
                 sechecker/Makefile \
                 seaudit/Makefile \
                 sediff/Makefile \
                 man/Makefile \
                 packages/Makefile])

AC_OUTPUT

echo "*** Configuration complete.  Do \`make help' to get a list of SETools targets."
