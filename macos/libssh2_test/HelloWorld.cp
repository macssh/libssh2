/*
 *  Copyright © 1997-2002 Metrowerks Corporation.  All Rights Reserved.
 *
 *  Questions and comments to:
 *       <mailto:support@metrowerks.com>
 *       <http://www.metrowerks.com/>
 */

#include <iostream>
#include <sioux.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "libssh2.h"

int main()
{
	SIOUXSettings.autocloseonquit = false;
	
	std::cout << "Hello World, this is CodeWarrior!" << std::endl;
	
	int rc;
	rc = libssh2_init(0);
	
    int sock = socket(AF_INET, SOCK_STREAM, 0);
#ifndef WIN32
    fcntl(sock, F_SETFL, 0);
#endif
	struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = inet_addr("192.168.2.145");
    rc = connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in));
    if (rc != 0) {
        fprintf(stderr, "failed to connect!\n");
        return 1;
    }
    
    /* Create a session instance and start it up
     * This will trade welcome banners, exchange keys, and setup crypto, compression, and MAC layers
     */
    LIBSSH2_SESSION *session = libssh2_session_init();
    libssh2_trace(session, INT_MAX);
    if (libssh2_session_startup(session, sock)) {
        fprintf(stderr, "Failure establishing SSH session\n");
        return 1;
    }
    
    {
        /* At this point we havn't authenticated,
	     * The first thing to do is check the hostkey's fingerprint against our known hosts
	     * Your app may have it hard coded, may go to a file, may present it to the user, that's your call
	     */
	    const char *fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	    printf("Fingerprint: ");
	    for(int i = 0; i < 20; i++) {
	        printf("%02X ", (unsigned char)fingerprint[i]);
	    }
	    printf("\n");
    }
    
    {
        /* check what authentication methods are available */
	    char *userauthlist = libssh2_userauth_list(session, "pip", 3);
	    printf("Authentication methods: %s\n", userauthlist);
	    int auth_pw;
	    if (strstr(userauthlist, "password") != NULL) {
	        auth_pw |= 1;
	    }
	    if (strstr(userauthlist, "keyboard-interactive") != NULL) {
	        auth_pw |= 2;
	    }
	    if (strstr(userauthlist, "publickey") != NULL) {
	        auth_pw |= 4;
	    }

	    {
	        printf("No supported authentication methods found!\n");
	        goto shutdown;
	    }
    }
   

shutdown:
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
	
	
	libssh2_exit();

	sleep(5);
	
	return 0;
}