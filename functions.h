//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP's Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: Secundary functions header file
// Date: 08/11/2005
//===========================================================================//

//===========================================================================//
// mailmonitor - Mail Monitor Implementation - Anti-Spam and Anti-virus
// by Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Copyright (C) 2005 Marcelo Duffles Donato Moreira
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//===========================================================================//

/*
 *  RCS COMMENTS
 *
 *  $Author: marcelo $
 *  $Date: 2005/12/14 02:37:38 $
 *  
 *  $Log: functions.h,v $
 *  Revision 1.5  2005/12/14 02:37:38  marcelo
 *  sending() added
 *
 *  Revision 1.4  2005/12/14 02:21:28  marcelo
 *  New functions added
 *
 *  Revision 1.3  2005/11/17 23:00:01  marcelo
 *  tcp_local_connect(), tcp_remote_connect() and proxy() prototypes added
 *
 *  Revision 1.2  2005/11/11 21:58:29  marcelo
 *  New functions prototypes added
 *
 *  Revision 1.1  2005/11/09 19:18:28  marcelo
 *  Initial revision
 *
 *       
 */

#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_ "@(#)functions.h $Revision: 1.5 $"

#include <netdb.h>
#include <time.h>

//#define __ML_CGI_GLOBAL_VARIABLES__

//====================================================================//
// Global variables
//====================================================================//
extern char *error_messages[];


//====================================================================//
// Secundary functions prototypes
//====================================================================//
void usage (void);
unsigned log_msg (char *message);
char *getLongFilename (char *path, char *filename);
int put_string (FILE *file, char *string);
int get_string (FILE *file, unsigned max_len, char *string);
void sigchld_handler (int s);
int sending (int socket, char *msg, int len, unsigned int flags);
int tcp_local_connect (int *sockfd, unsigned local_port);
int tcp_remote_connect (int *sockfd, unsigned remote_port,
			struct hostent *server_addr);
char *get_username (char *username, char *buffer);
char is_in_header (char *header, char *spam_addr);
int delete_msg (int server_fd, unsigned msg_nb);
int delete_spam (int server_fd, char *username,
		 char *black_list_dir);
int proxy (int *client_fd, struct hostent *server_addr,
	   unsigned pop3_server_port, char *black_list_dir);
int createNewCookieFile (char *cookieName, char *cookieValue, time_t cookieExpiration, char *ip);
int createRandomString (char *validCharacters, unsigned length, char *randomString);
int cookieFileExist (char *username);
int autenticateUser (char *username, char *pass);
void showHtmlErrorPage (unsigned errorCode);
int getCookieValue (char *cookieName, char *cookieValue);
void showWebUserMenu (char *cookieName);
int validateCookie (char *cookieName, char *cookieValue, char *ip);
void showHtmlInitialPage (char *cookieName);
void showHtmlWelcomePage (char *username);
int get_black_list_dir (char *black_list_dir);


	   
#endif /* _FUNCTIONS_H_ */

/* $RCSfile: functions.h,v $ */
