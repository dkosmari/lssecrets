#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([lssecrets],
        [1.1],
        [https://github.com/dkosmari/lssecrets/issues],
        [lssecrets],
        [https://github.com/dkosmari/lssecrets])
AC_CONFIG_SRCDIR([main.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign])

AX_APPEND_COMPILE_FLAGS([-std=c++20], [CXXFLAGS])
AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
PKG_CHECK_MODULES([LIBSECRET], [libsecret-unstable])

PKG_CHECK_MODULES([GLIBMM], [glibmm-2.68 giomm-2.68],
                  [AC_DEFINE([HAVE_GLIBMM_2_68], [1], [Define when glibmm ABI is 2.68+])],
                  [PKG_CHECK_MODULES([GLIBMM], [glibmm-2.4 giomm-2.4])])



# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
