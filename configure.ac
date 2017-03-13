# This is based on David A. Wheeler's template for configure.ac

# Process this file with autoconf to produce a configure script.

# Initialize autoconf.
AC_INIT([choparp], [20150613])
# Force autoconf to be at least this version number:
AC_PREREQ([2.68])
# Safety check - list a source file that wouldn't be in other directories:
AC_CONFIG_SRCDIR([src/choparp.c])
# Put configuration results here, so we can easily #include them:
AC_CONFIG_HEADERS([config.h])
# Put autotools auxiliary files in subdirectories to reduce clutter:
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror])
AC_CONFIG_FILES([Makefile])

# TAP test driver support
AC_PROG_AWK
AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Checks for programs, e.g., AC_PROG_CC
AC_PROG_CC
# only needef for automake < 1.14
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_lookupdev], [], [AC_MSG_ERROR([missing required library libpcap])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h],
    [], [AC_MSG_ERROR([missing required platform headers])])
AC_CHECK_HEADER([pcap.h], [], [AC_MSG_ERROR([missing required header pcap.h])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ftruncate inet_ntop memset socket strchr strtol])

# Do final output.
AC_OUTPUT
