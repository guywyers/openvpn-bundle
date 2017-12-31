AC_PREREQ([2.68])
AC_INIT([openvpn-bundle], 20171228)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([crypto], [HMAC_CTX_init], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_LIB([uuid], [uuid_generate], [], [AC_MSG_ERROR([UUID library required])])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h netinet/in.h stdint.h string.h], [],[AC_MSG_ERROR([Missing system headers])]   )
AC_CHECK_HEADERS([openssl/evp.h openssl/hmac.h], [],[AC_MSG_ERROR([OpenSSL headers missing])])
AC_CHECK_HEADERS([uuid/uuid.h], [],[AC_MSG_ERROR([UUID header missing])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp strchr strncasecmp])


AC_OUTPUT(Makefile src/Makefile)
