/**
* @file net.c  Networking code.
*
* Copyright (C) 2010 Creytiv.com
*/
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#include <stdlib.h>
#include <string.h>
#if !defined(WIN32) && !defined(CYGWIN)
#define __USE_BSD 1  /**< Use BSD code */
#include <unistd.h>
#include <netdb.h>
#endif
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_net.h>


#define DEBUG_MODULE "net"
#define DEBUG_LEVEL 5
#include <re_dbg.h>
#include "..\include\re_mem.h"
#include <ws2spi.h>


/* Return as a string the error description for err */
static char *
wstrerror(LONG err)
{
	static LPVOID lpMsgBuf;

	if (lpMsgBuf)
		LocalFree(lpMsgBuf);

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,		// GetLastError() does not seem to work reliably here
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);

	return lpMsgBuf;
}


/*
* Return an IFS socket. This can be used for ReadFile/WriteFile
*/
SOCKET
ifs_socket(int af, int type, int proto)
{
	unsigned long pblen = 0;
	SOCKET ret;
	WSAPROTOCOL_INFOW *pbuff;
	WSAPROTOCOL_INFOA pinfo;
	int nprotos, i, err;

	if (WSCEnumProtocols(NULL, NULL, &pblen, &err) != SOCKET_ERROR) {
		DEBUG_WARNING("No socket protocols available");
		return INVALID_SOCKET;
	}
		
	if (err != WSAENOBUFS) {
		DEBUG_WARNING("WSCEnumProtocols failed: %s", wstrerror(err));
		return INVALID_SOCKET;
	}
		

	pbuff = (WSAPROTOCOL_INFOW *)mem_alloc(pblen, NULL);

	if ((nprotos = WSCEnumProtocols(NULL, pbuff, &pblen, &err)) == SOCKET_ERROR) {
		DEBUG_WARNING("WSCEnumProtocols failed: %s", wstrerror(err));
		return INVALID_SOCKET;
	}
		

	for (i = 0; i < nprotos; i++) {
		if ((af != AF_UNSPEC && af != pbuff[i].iAddressFamily)
			|| (type != pbuff[i].iSocketType)
			|| (proto != 0 && pbuff[i].iProtocol != 0 &&
				proto != pbuff[i].iProtocol))
			continue;
		if (!(pbuff[i].dwServiceFlags1 & XP1_IFS_HANDLES))
			continue;

		memcpy(&pinfo, pbuff + i, sizeof(pinfo));
		wcstombs(pinfo.szProtocol, pbuff[i].szProtocol, sizeof(pinfo.szProtocol));
		mem_deref(pbuff);

		if ((ret = WSASocket(af, type, proto, &pinfo, 0, 0)) == INVALID_SOCKET) {
			DEBUG_WARNING("WSASocket failed: %s", wstrerror(WSAGetLastError()));
			return INVALID_SOCKET;
		}
			
		return ret;
	}

	return INVALID_SOCKET;
}