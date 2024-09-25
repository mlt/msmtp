#ifndef CONFIG_H
#define CONFIG_H

#define W32_NATIVE 1

#define popen _popen
#define pclose _pclose
#define strdup _strdup

#define VERSION "1.8.26"
#define PACKAGE "msmtp"
#define PACKAGE_NAME "msmtp"
#define PLATFORM "x64-windows"
#define PACKAGE_BUGREPORT "marlam@marlam.de"

#define HAVE_LIBSSL
#define HAVE_TLS
#define USE_CREDMAN
//#define HAVE_LIBIDN
//#define ENABLE_NLS 1
//#define LOCALEDIR "../locale"
#define TLS_LIB "Schannel"
//#define TLS_LIB "WolfSSL"
//#define OPENSSL_EXTRA
//#define OPENSSL_VERSION_NUMBER 0x10100000L

#endif
