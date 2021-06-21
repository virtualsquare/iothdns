#ifndef IOTHDNS_GETSERV_H
#define IOTHDNS_GETSERV_H

/* iothdns_getservice maps a service string to its corresponding port #
 * using a file following the syntax of services(5) */
int iothdns_getservice(const char *servicefile, const char *servicename, const char *protocol);

/* iothdns_getservice_rev maps a port number to its corresponding service string
 * using a file following the syntax of services(5) */
int iothdns_getservice_rev(const char *servicefile, int port, const char *protocol,
    char *serv, size_t servlen, int numeric);

#endif

