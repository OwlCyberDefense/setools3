AC_INIT(setools, 3.3.5, [Tresys Technology <setools@tresys.com>], [setools])
AC_PREREQ([2.59])
AC_CONFIG_SRCDIR(libqpol/src/policy.c)
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([-Wno-portability])

dnl *** update these variables as versions change; also update AC_INIT ***

libqpol_soversion=1
libqpol_version=1.4

libapol_soversion=4
libapol_version=4.1.4

libpoldiff_soversion=1
libpoldiff_version=1.3.1

libsefs_soversion=4
libsefs_version=4.0.2

libseaudit_soversion=4
libseaudit_version=4.2.1

setoolsdir='${prefix}/share/setools-3.3'
javadir='${prefix}/share/java'

version_min_sepol_major=1
version_min_sepol_minor=12
version_min_sepol_patch=27

dnl *** end of tunable values ***

libqpol_soname=libqpol.so.${libqpol_soversion}
libqpol_pyswig_soname=_qpol.so.${libqpol_soversion}
libqpol_jswig_soname=libjqpol.so.${libqpol_soversion}
libqpol_tswig_soname=libtqpol.so.${libqpol_soversion}

libapol_soname=libapol.so.${libapol_soversion}
libapol_pyswig_soname=_apol.so.${libapol_soversion}
libapol_jswig_soname=libjapol.so.${libapol_soversion}
libapol_tswig_soname=libtapol.so.${libapol_soversion}

libpoldiff_soname=libpoldiff.so.${libpoldiff_soversion}
libpoldiff_pyswig_soname=_poldiff.so.${libpoldiff_soversion}
libpoldiff_jswig_soname=libjpoldiff.so.${libpoldiff_soversion}
libpoldiff_tswig_soname=libtpoldiff.so.${libpoldiff_soversion}

libsefs_soname=libsefs.so.${libsefs_soversion}
libsefs_pyswig_soname=_sefs.so.${libsefs_soversion}
libsefs_jswig_soname=libjsefs.so.${libsefs_soversion}
libsefs_tswig_soname=libtsefs.so.${libsefs_soversion}

libseaudit_soname=libseaudit.so.${libseaudit_soversion}
libseaudit_pyswig_soname=_seaudit.so.${libseaudit_soversion}
libseaudit_jswig_soname=libjseaudit.so.${libseaudit_soversion}
libseaudit_tswig_soname=libtseaudit.so.${libseaudit_soversion}

AC_GNU_SOURCE
AC_PROG_CC_C99
if test ${ac_cv_prog_cc_c99} = "no"; then
  AC_MSG_ERROR([SETools requires a C99-compliant C compiler to build.])
fi
AC_PROG_CXX
AC_LANG([C])
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_HEADER_STDBOOL
AC_C_BIGENDIAN
AC_CHECK_FUNCS(rand_r)
AC_SYS_LARGEFILE

AC_CACHE_SAVE

if test "x${enable_shared}" = xyes; then
    use_shared=yes
else
    use_shared=no
fi

AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug],
                             [compile with full debugging support]),
              enable_debug="$enableval")
AC_MSG_CHECKING([for debugging support])
if test "x${enable_debug}" = xyes; then
    DEBUGCFLAGS="-g3 -gdwarf-2 -O0 -Wall -DSETOOLS_DEBUG=1 -fno-strict-aliasing"
    DEBUGCXXFLAGS="-g3 -gdwarf-2 -O0 -Wall -DSETOOLS_DEBUG=1 -fno-strict-aliasing"
    DEBUGJFLAGS="-g"
    DEBUGLDFLAGS="-g -lm"
    QPOL_LIB_FLAG='$(top_builddir)/libqpol/src/libqpol.so -Wl,-rpath=$(top_builddir)/libqpol/src'
    APOL_LIB_FLAG='$(top_builddir)/libapol/src/libapol.a -Wl,-rpath=$(top_builddir)/libapol/src'
    SEFS_LIB_FLAG='$(top_builddir)/libsefs/src/libsefs.a -Wl,-rpath=$(top_builddir)/libsefs/src'
    POLDIFF_LIB_FLAG='$(top_builddir)/libpoldiff/src/libpoldiff.a -Wl,-rpath=$(top_builddir)/libpoldiff/src'
    SEAUDIT_LIB_FLAG='$(top_builddir)/libseaudit/src/libseaudit.a -Wl,-rpath=$(top_builddir)/libseaudit/src'
    use_shared=no
    AC_MSG_RESULT(yes)
else
    AC_DEFINE(NDEBUG, 1, [disable calls to assert()])
    DEBUGCFLAGS="-fno-strict-aliasing"
    DEBUGCXXFLAGS="-fno-strict-aliasing"
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
AC_SUBST(DEBUGCXXFLAGS)
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

AC_MSG_CHECKING([for how to link against libraries])
if test ${use_shared} = yes; then
    AC_MSG_RESULT(shared)
else
    AC_MSG_RESULT(static)
fi

AC_ARG_ENABLE(warnall,
              AC_HELP_STRING([--enable-warnall],
                             [compile with most warnings enabled]),
              enable_warnall="$enableval")
if test "x${enable_warnall}" = xyes; then
    WARNCFLAGS=" -O1 -Wall -Wshadow -Wundef -pedantic -Wuninitialized -fno-strict-aliasing -std=c99"
    WARNCXXFLAGS=" -O1 -Wall -Wshadow -Wundef -pedantic -Wuninitialized -Wabi -fno-strict-aliasing -Wno-variadic-macros"
    WARNJFLAGS=" -verbose"
    WARNLDFLAGS=""
else
    WARNCFLAGS=""
    WARNCXXFLAGS=""
    WARNJFLAGS=""
    WARNLDFLAGS=""
fi
AC_SUBST(WARNCFLAGS)
AC_SUBST(WARNCXXFLAGS)
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
   if test x"${ac_cv_c_tclconfig}" = x ; then
     AC_MSG_ERROR([No Tcl install found.])
   fi
   TEA_LOAD_TCLCONFIG
   AC_MSG_CHECKING([for Tcl 8.4 or greater])
   if test \( "${TCL_MAJOR_VERSION}" -gt 8 \) -o \( "${TCL_MAJOR_VERSION}" -eq 8 -a "${TCL_MINOR_VERSION}" -ge 4 \); then
      AC_MSG_RESULT(yes)
   else
      AC_MSG_ERROR([setools requires Tcl 8.4 or greater])
   fi
   TEA_PUBLIC_TCL_HEADERS
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

# check for Tk if both --enable-swig-tcl and --enable-gui are given
if test ${build_apol} = "yes"; then
   TEA_PATH_TKCONFIG
   if test x"${ac_cv_c_tkconfig}" = x ; then
     AC_MSG_ERROR([No Tk install found.])
   fi
   TEA_LOAD_TKCONFIG
   AC_MSG_CHECKING([for Tk 8.4 or greater])
   if test \( "${TK_MAJOR_VERSION}" -gt 8 \) -o \( "${TK_MAJOR_VERSION}" -eq 8 -a "${TK_MINOR_VERSION}" -ge 4 \); then
      AC_MSG_RESULT(yes)
   else
      AC_MSG_ERROR([setools requires Tk 8.4 or greater])
   fi
   TEA_PUBLIC_TK_HEADERS
   TEA_PATH_X
   TEA_PROG_WISH
fi

AC_ARG_ENABLE(bwidget-check,
              AC_HELP_STRING([--disable-bwidget-check],
                             [do not check for BWidget 1.8, assume it exists]),
              enable_bwidget="$enableval",
              enable_bwidget="yes")
if test ${build_apol} = "no"; then
    enable_bwidget=no
else
    AC_MSG_CHECKING([for BWidget 1.7 or greater])
fi

TCL_AUTOPATH=''
if test "x${enable_bwidget}" = "xyes"; then
    # certain distributions do not properly set the auto_path to point
    # to Tk, so try to detect it here
    changequote(<<<,>>>)dnl
    (echo "if {[catch {package require Tk}]} {exit 1} ; exit 0" | ${TCLSH_PROG}) || \
        TCL_AUTOPATH=$(find ${TK_EXEC_PREFIX}  -maxdepth 3 -name pkgIndex.tcl -path '*tk*' -printf %h)
    echo "lappend auto_path ${TCL_AUTOPATH}" > ./conftest.tcl
    cat >> ./conftest.tcl <<EOF
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
            AC_MSG_RESULT([1.7; will patch apol for compatibility])
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
        changequote(<<<,>>>)dnl
        echo 'puts [file join $tcl_library BWidget1.8]' > ./conftest.tcl
        changequote([,])dnl
        BWIDGET_DESTDIR=`${TCLSH_PROG} ./conftest.tcl`
        AC_SUBST(BWIDGET_DESTDIR)
    fi
else
    AC_MSG_RESULT([skipped, assuming 1.8+ is installed])
    copy_bwidget=no
    bwidget_ver=1.8
fi

if test "x${enable_debug}" = xyes; then
   TCL_AUTOPATH+=' $(top_builddir)/libqpol/swig/tcl $(top_builddir)/libapol/swig/tcl $(top_builddir)/libsefs/swig/tcl $(top_builddir)/libpolsearch/swig/tcl $(top_builddir)/apol'
else
   TCL_AUTOPATH+=' $(libdir)/setools'
fi
AC_SUBST(TCL_AUTOPATH)


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
  if test -f ${sepol_devel_libdir}/libsepol.so ; then
    break
  fi
done
for dir in lib64 lib ; do
  selinux_devel_libdir="${selinux_devel}/${dir}"
  if test -f ${selinux_devel_libdir}/libselinux.so ; then
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

AC_ARG_ENABLE(sepol-src,
              AC_HELP_STRING([--enable-sepol-src=PATH],
                             [use another sepol source tree at PATH (developer only flag)]),
              sepol_srcdir="$enableval",
              sepol_srcdir="")
if test "x${sepol_srcdir}" = "x"; then
   sepol_srcdir=${sepol_devel_libdir}
   AC_CHECK_FILE([${sepol_srcdir}/libsepol.a],,
      AC_MSG_ERROR([make sure libsepol-devel is installed]))
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
   AC_CHECK_FILE([${sepol_srcdir}/libsepol.a],,
      AC_MSG_ERROR([could not find precompiled libsepol.a]))
   sepol_devel_incdir="${sepol_srcdir}/../include"
fi
SELINUX_CFLAGS="-I${sepol_devel_incdir} -I${selinux_devel_incdir}"
AC_SUBST(SELINUX_CFLAGS)
AC_SUBST(SELINUX_LIB_FLAG)

dnl ** check for certain features of libsepol

sepol_save_CFLAGS="${CFLAGS}"
sepol_save_CPPFLAGS="${CPPFLAGS}"
CFLAGS="${CFLAGS} ${SELINUX_CFLAGS} ${SELINUX_LIB_FLAG}"
CPPFLAGS="${CPPFLAGS} ${SELINUX_CFLAGS}"

dnl check for user and role mapping, added in libsepol version 2.0.29
AC_MSG_CHECKING([for user and role mappings])
AC_COMPILE_IFELSE(
                  [AC_LANG_SOURCE([
#include <sepol/policydb/expand.h>
int main () {
  return role_set_expand(NULL, NULL, NULL, NULL);
}])],
                  sepol_new_user_role_mapping="yes",
                  sepol_new_user_role_mapping="no")
AC_MSG_RESULT([${sepol_new_user_role_mapping}])

dnl check for permissive types, added in libsepol version 2.0.26
AC_CHECK_DECL([TYPE_FLAGS_PERMISSIVE],
                sepol_new_permissive_types="yes",
                sepol_new_permissive_types="no",
                [#include <sepol/policydb/policydb.h>])

dnl check for modified AV tab behavior, introduced in libsepol version 2.0.20
AC_CHECK_DECL([avtab_alloc],
              sepol_new_avtab="yes",
              sepol_new_avtab="no",
              [#include <sepol/policydb/conditional.h>])

dnl check for policycap, added in libsepol version 2.0.18
AC_CHECK_MEMBER([struct policydb.policycaps.node],
                sepol_new_policycaps="yes",
                sepol_new_policycaps="no",
                [#include <sepol/policydb/policydb.h>])

dnl check for broken boolmap behavior in libsepol version 2.0.2
AC_CHECK_DECL([cond_node_create], sepol_check_boolmap="yes", sepol_check_boolmap="no", [#include <sepol/policydb/conditional.h>])
if test ${sepol_check_boolmap} = "yes"; then
    dnl check for boolmap parameter that is fixed in version 2.0.3 through
    dnl 2.0.28.  version 2.0.29 (see check above) implies that this check
    dnl will succeed.
    if test ${sepol_new_user_role_mapping} = "no"; then
        AC_MSG_CHECKING([for corrected libsepol boolean expand behavior])
        AC_COMPILE_IFELSE(
                         [AC_LANG_SOURCE([
#include <sepol/policydb/expand.h>
int main () {
  return expand_module_avrules(NULL, NULL, NULL, NULL, NULL, 0, 0);
}])],
                         AC_MSG_RESULT([yes]),
                         AC_MSG_ERROR([this version of libsepol is incompatible with SETools]))
    fi
    sepol_new_expand_boolmap="yes"
else
    sepol_new_expand_boolmap="no"
fi

dnl check for new error code format, added in libsepol 2.0.0
AC_CHECK_HEADER([sepol/errcodes.h],
	        sepol_new_defines="yes",
                sepol_new_defines="no")

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

AC_ARG_WITH(test-policies,
            AC_HELP_STRING([--with-test-policies],
                           [directory containing test policies (developer only flag)]),
            test_policies="$withval",
            test_policies=".")

AC_CACHE_SAVE

dnl check for pkg-config
AC_CHECK_PROG(has_pkg_config, pkg-config, yes, no)
if test ${has_pkg_config} = "no"; then
   AC_MSG_ERROR([pkg-config not found])
fi

AC_MSG_CHECKING([for libxml])
pkg-config --exists 'libxml-2.0'
if test $? -ne 0 ; then
  AC_MSG_ERROR([setools requires libxml-2.0])
fi
XML_CFLAGS=`pkg-config --cflags libxml-2.0`
XML_LIBS=`pkg-config --libs libxml-2.0`
AC_MSG_RESULT([yes])
AC_SUBST(XML_CFLAGS)
AC_SUBST(XML_LIBS)

AC_MSG_CHECKING([for sqlite3])
pkg-config --exists 'sqlite3 >= 3.2.0'
if test $? -ne 0 ; then
  AC_MSG_ERROR([setools requires sqlite3 3.2.0 or greater])
fi
SQLITE3_CFLAGS=`pkg-config --cflags sqlite3`
SQLITE3_LIBS=`pkg-config --libs sqlite3`
AC_MSG_RESULT([yes])
AC_SUBST(SQLITE3_CFLAGS)
AC_SUBST(SQLITE3_LIBS)

SEAUDIT_LIB_FLAG+=" ${XML_LIBS}"
SEFS_LIB_FLAG+=" ${SQLITE3_LIBS}"

gtk_version_2_8=1
if test "x${build_gui}" = xyes; then

  AC_MSG_CHECKING([for GTK])
  pkg-config --atleast-version=2.4 gtk+-2.0
  if test $? -ne 0; then
     AC_MSG_ERROR([setools requires GTK+ 2.4 or greater])
  fi
  pkg-config --atleast-version=2.8 gtk+-2.0
  gtk_version_2_8=$?
  GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
  GTK_LIBS=`pkg-config --libs gtk+-2.0`
  AC_MSG_RESULT([yes])
  AC_SUBST(GTK_CFLAGS)
  AC_SUBST(GTK_LIBS)

  AC_MSG_CHECKING([for libglade])
  pkg-config --exists 'libglade-2.0'
  if test $? -ne 0; then
     AC_MSG_ERROR([setools requires libglade-2.0])
  fi
  GLADE_CFLAGS=`pkg-config --cflags libglade-2.0`
  GLADE_LIBS=`pkg-config --libs libglade-2.0`
  AC_MSG_RESULT([yes])
  AC_SUBST(GLADE_CFLAGS)
  AC_SUBST(GLADE_LIBS)

  AC_MSG_CHECKING([for gdk-pixbuf])
  pkg-config --exists 'gdk-pixbuf-2.0'
  if test $? -ne 0; then
     AC_MSG_ERROR([setools requires gdk-pixbuf-2.0])
  fi
  PIXBUF_CFLAGS=`pkg-config --cflags gdk-pixbuf-2.0`
  PIXBUF_LIBS=`pkg-config --libs gdk-pixbuf-2.0`
  AC_MSG_RESULT([yes])
  AC_SUBST(PIXBUF_CFLAGS)
  AC_SUBST(PIXBUF_LIBS)

  AC_MSG_CHECKING([for gthread])
  pkg-config --exists 'gthread-2.0'
  if test $? -ne 0; then
     AC_MSG_ERROR([setools requires gthread-2.0])
  fi
  GTHREAD_CFLAGS=`pkg-config --cflags gthread-2.0`
  GTHREAD_LIBS=`pkg-config --libs gthread-2.0`
  AC_MSG_RESULT([yes])
  AC_SUBST(GTHREAD_CFLAGS)
  AC_SUBST(GTHREAD_LIBS)
fi

have_cunit="no"
AC_CHECK_LIB(cunit, CU_initialize_registry, have_cunit="yes", AC_MSG_WARN([CUnit not found; `make check' will fail.]))
if test ${have_cunit} = "yes"; then
  CUNIT_LIB_FLAG="-lcunit"
  AC_SUBST(CUNIT_LIB_FLAG)
fi
#AC_MSG_CHECKING([for FUSE])
#pkg-config --exists fuse
#if test $? -ne 0; then
#   AC_MSG_WARN([FUSE not found; libsefs tests will not be built])
#   have_fuse="no"
#else
#   FUSE_CFLAGS=`pkg-config --cflags fuse`
#   FUSE_LIBS=`pkg-config --libs fuse`
#   AC_SUBST(FUSE_CFLAGS)
#   AC_SUBST(FUSE_LIBS)
#   have_fuse="yes"
#   AC_MSG_RESULT([yes])
#fi

dnl set up variables here
if test ${use_selinux} = "yes"; then
   AC_DEFINE(LIBSELINUX, 1, [enable libselinux-specific code])
fi

AM_CONDITIONAL(DO_SWIGIFY, test ${do_swigify} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_PYTHON, test ${do_swigify_python} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_JAVA, test ${do_swigify_java} = "yes")
AM_CONDITIONAL(DO_SWIGIFY_TCL, test ${do_swigify_tcl} = "yes")
AM_CONDITIONAL(COPY_BWIDGET, test ${copy_bwidget} = "yes")
AM_CONDITIONAL(BUILD_APOL, test ${build_apol} = "yes")
AM_CONDITIONAL(BUILD_GUI, test ${build_gui} = "yes")
#AM_CONDITIONAL(DO_FUSE, test ${have_fuse} = "yes")

profile_install_dir='${setoolsdir}/sechecker-profiles'

AC_SUBST(VERSION)
AC_SUBST(javadir)
AC_SUBST(sepol_srcdir)
AC_SUBST(libqpol_soversion)
AC_SUBST(libqpol_version)
AC_SUBST(libqpol_soname)
AC_SUBST(libqpol_pyswig_soname)
AC_SUBST(libqpol_jswig_soname)
AC_SUBST(libqpol_tswig_soname)
AC_SUBST(libapol_soversion)
AC_SUBST(libapol_version)
AC_SUBST(libapol_soname)
AC_SUBST(libapol_pyswig_soname)
AC_SUBST(libapol_jswig_soname)
AC_SUBST(libapol_tswig_soname)
AC_SUBST(libpoldiff_soversion)
AC_SUBST(libpoldiff_version)
AC_SUBST(libpoldiff_soname)
AC_SUBST(libpoldiff_pyswig_soname)
AC_SUBST(libpoldiff_jswig_soname)
AC_SUBST(libpoldiff_tswig_soname)
AC_SUBST(libsefs_soversion)
AC_SUBST(libsefs_version)
AC_SUBST(libsefs_soname)
AC_SUBST(libsefs_pyswig_soname)
AC_SUBST(libsefs_jswig_soname)
AC_SUBST(libsefs_tswig_soname)
AC_SUBST(libseaudit_soversion)
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
AC_DEFINE_UNQUOTED(TEST_POLICIES, "${test_policies}", [location of testing policies])

if test ${sepol_new_defines} != "yes" ; then
   AC_DEFINE(SEPOL_ENOMEM, HASHTAB_OVERFLOW, [remap of libsepol 1.x.x define to 2.x.x])
   AC_DEFINE(SEPOL_EEXIST, HASHTAB_PRESENT, [remap of libsepol 1.x.x define to 2.x.x])
fi
if test ${sepol_new_expand_boolmap} == "yes" ; then
   AC_DEFINE(HAVE_SEPOL_BOOLMAP, 1, [sepol's new expand boolmap behavior])
fi
if test ${sepol_new_policycaps} == "yes"; then
   AC_DEFINE(HAVE_SEPOL_POLICYCAPS, 1, [if libsepol has policycaps])
fi
if test ${sepol_new_avtab} == "yes"; then
   AC_DEFINE(SEPOL_DYNAMIC_AVTAB, 1, [if avtab sizes are calculated dynamically by loader or are hardcoded])
fi
if test ${sepol_new_permissive_types} == "yes"; then
   AC_DEFINE(HAVE_SEPOL_PERMISSIVE_TYPES, 1, [if types can be marked as permissive])
fi
if test ${sepol_new_user_role_mapping} == "yes"; then
   AC_DEFINE(HAVE_SEPOL_USER_ROLE_MAPPING, 1, [if users and roles are mapped during policy expansion])
fi

if test ${use_shared} == "yes"; then
   AC_DEFINE(LINK_SHARED, 1, [link programs using shared libraries])
else
   AC_DEFINE(LINK_SHARED, 0, [link programs using shared libraries])
fi

if test ${gtk_version_2_8} -eq 0 ; then
   AC_DEFINE(GTK_2_8, 1, [GTK+ is version 2.8+])
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
    if {![catch {uplevel \#0 source tkcon.tcl}]} {
        package require tkcon
        bind . <F8> {tkcon show}
    }
EOF
   fi
   echo "}" >> ./config.tcl
   echo "proc tcl_config_get_version {} {" >> ./config.tcl
   echo "    return ${version}" >> ./config.tcl
   echo "}" >> ./config.tcl
]], [bwidget_ver=$bwidget_ver; enable_debug=$enable_debug; version=$VERSION])

AC_CONFIG_FILES([Makefile VERSION \
                 libqpol/Makefile libqpol/src/Makefile libqpol/include/Makefile libqpol/include/qpol/Makefile libqpol/tests/Makefile \
                 libqpol/swig/Makefile libqpol/swig/python/Makefile libqpol/swig/java/Makefile libqpol/swig/java/MANIFEST.MF libqpol/swig/tcl/Makefile \
                 libapol/Makefile libapol/src/Makefile libapol/include/Makefile libapol/include/apol/Makefile libapol/tests/Makefile \
                 libapol/swig/Makefile libapol/swig/python/Makefile libapol/swig/java/Makefile libapol/swig/java/MANIFEST.MF libapol/swig/tcl/Makefile \
                 libpoldiff/Makefile libpoldiff/src/Makefile libpoldiff/include/Makefile libpoldiff/include/poldiff/Makefile libpoldiff/tests/Makefile \
                 libpoldiff/swig/Makefile libpoldiff/swig/python/Makefile libpoldiff/swig/java/Makefile libpoldiff/swig/java/MANIFEST.MF libpoldiff/swig/tcl/Makefile \
                 libsefs/Makefile libsefs/src/Makefile libsefs/include/Makefile libsefs/include/sefs/Makefile libsefs/tests/Makefile \
                 libsefs/swig/Makefile libsefs/swig/python/Makefile libsefs/swig/java/Makefile libsefs/swig/tcl/Makefile libsefs/swig/java/MANIFEST.MF \
                 libseaudit/Makefile libseaudit/src/Makefile libseaudit/include/Makefile libseaudit/include/seaudit/Makefile libseaudit/tests/Makefile \
                 libseaudit/swig/Makefile libseaudit/swig/python/Makefile libseaudit/swig/java/Makefile libseaudit/swig/java/MANIFEST.MF libseaudit/swig/tcl/Makefile \
                 secmds/Makefile \
                 apol/Makefile \
                 sechecker/Makefile \
                 seaudit/Makefile \
                 sediff/Makefile \
                 man/Makefile \
                 debian/Makefile \
                 packages/Makefile packages/rpm/Makefile \
                 packages/libqpol.pc packages/libapol.pc packages/libpoldiff.pc packages/libseaudit.pc packages/libsefs.pc])

AC_OUTPUT

echo "*** Configuration complete.  Do \`make help' to get a list of SETools targets."
