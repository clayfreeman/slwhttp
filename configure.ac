#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([slwhttp], [1.0], [git@clayfreeman.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main.cpp])
AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_RANLIB

# Checks for header files.
AC_CHECK_HEADERS(
  [fcntl.h],
  [],
  [AC_MSG_ERROR([couldn't find or include fcntl.h])],
  []
)
AC_CHECK_HEADERS(
  [limits.h],
  [],
  [AC_MSG_ERROR([couldn't find or include limits.h])],
  []
)
AC_CHECK_HEADERS(
  [netinet/in.h],
  [],
  [AC_MSG_ERROR([couldn't find or include netinet/in.h])],
  []
)
AC_CHECK_HEADERS(
  [stdlib.h],
  [],
  [AC_MSG_ERROR([couldn't find or include stdlib.h])],
  []
)
AC_CHECK_HEADERS(
  [string.h],
  [],
  [AC_MSG_ERROR([couldn't find or include string.h])],
  []
)
AC_CHECK_HEADERS(
  [sys/sendfile.h],
  [],
  [AC_MSG_ERROR([couldn't find or include sys/sendfile.h])],
  []
)
AC_CHECK_HEADERS(
  [sys/socket.h],
  [],
  [AC_MSG_ERROR([couldn't find or include sys/socket.h])],
  []
)
AC_CHECK_HEADERS(
  [sys/time.h],
  [],
  [AC_MSG_ERROR([couldn't find or include sys/time.h])],
  []
)
AC_CHECK_HEADERS(
  [unistd.h],
  [],
  [AC_MSG_ERROR([couldn't find or include unistd.h])],
  []
)

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset realpath select socket strdup])

AC_OUTPUT([Makefile src/Makefile])
