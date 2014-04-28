//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP's Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: Constants header file
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
 *  $Date: 2005/12/14 02:21:43 $
 *  
 *  $Log: const.h,v $
 *  Revision 1.2  2005/12/14 02:21:43  marcelo
 *  New constans added
 *
 *  Revision 1.1  2005/12/05 17:57:39  marcelo
 *  Initial revision
 *
 */

#ifndef _CONST_H_
#define _CONST_H_ "$Revision: 1.2 $"


//====================================================================//
// Configuration constants (default values)
//====================================================================//

#ifndef DATA_DIR
//#define DATA_DIR		"/lab/users/Otto/marcelo"
//#define DATA_DIR		"/home/marcelo"
#define DATA_DIR		"/home/zeus4/marceloddm/mailmonitor/data"
#endif /* DATA_DIR */

#ifndef COOKIES_DIR
#define COOKIES_DIR		"/home/zeus4/marceloddm/mailmonitor/data/cookies"
#endif /* COOKIES_DIR */

#ifndef IMAGES_DIR
#define IMAGES_DIR		"/home/zeus4/marceloddm/mailmonitor/data/images"
#endif /* IMAGES_DIR */

#ifndef HTML_CGIS_DIR
#define HTML_CGIS_DIR		"http://www2.del.ufrj.br/~marceloddm/mailmonitor/cgi"
#endif /* CGIS_DIR */

#ifndef HTML_IMAGES_DIR
#define HTML_IMAGES_DIR		"http://www2.del.ufrj.br/~marceloddm/mailmonitor/images"
#endif /* IMAGES_DIR */

#ifndef HTML_WEB_DIR
#define HTML_WEB_DIR		"http://www2.del.ufrj.br/~marceloddm/mailmonitor"
#endif /* WEB_DIR */

#ifndef LOG_FILE_NAME
#define LOG_FILE_NAME		"mailmonitor.log"
#endif /* LOG_FILE_NAME */

#ifndef CONF_FILE_NAME
#define CONF_FILE_NAME		"conf.dat"
#endif /* CONF_FILE_NAME */

#ifndef POP3_SERVER_PORT
#define POP3_SERVER_PORT	12345
#endif /* POP3_SERVER_PORT */


//====================================================================//
// Main program constants
//====================================================================//

/* minimum number of options */
#define MIN_NB_OPTIONS	4
/* maximum number of options */
#define MAX_NB_OPTIONS	5

/* minimum number of arguments */
#define MIN_NB_ARGS	9
/* maximum number of arguments */
#define MAX_NB_ARGS	10


//====================================================================//
// Secundary functions constants
//====================================================================//

/* Pending connections in server queue */
#define MAX_CONNECTIONS			10    

/* Maximum buffer length */
#define MAX_BUF_LEN			512

/* Maximum username length */
#define MAX_USERNAME_LEN		100

/* Maximum password length */
#define MAX_PASS_LEN			100

/* Maximum domain length */
#define MAX_DOMAIN_LEN			100

/* Maximum email length */
#define MAX_EMAIL_LEN			(MAX_USERNAME_LEN + MAX_DOMAIN_LEN)

#define MAX_LENGTH_IP			15 
#define COOKIE_NAME_LENGTH		(MAX_USERNAME_LEN)
#define COOKIE_VALUE_LENGTH		64
#define COOKIE_EXPIRATION		1800
#define COOKIE_VALUE_VALID_CHARACTERS  "abcdefghijklmnopqrstuvxyzwABCDEFGHIJKLMNOPQRSTUVXYZW0123456789"

/* POP3 commands */
#define NOOP				0
#define USER				1
#define QUIT				2
#define PASS				3
#define MULTILINE			4


//====================================================================//
// Error constants
//====================================================================//

#define END_OF_FILE			-2
#define ERROR				-1
#define OK				0
#define E_CREATING_CHILD_SESSION	1
#define E_CHANGING_DIRECTORY		2
#define E_CLOSING_STANDARD_FILES	3
#define E_LOG_MSG			4
#define E_GETHOSTNAME			5
#define E_GETHOSTBYNAME			6
#define E_SOCKET			7
#define E_BIND				8
#define E_LISTEN			9
#define E_SIGACTION			10
#define E_ACCEPT			11
#define E_SEND				12
#define E_INVAL_LOCAL_PORT		13
#define E_INVAL_POP3_SERVER_PORT	14
#define E_RECV				15
#define E_TCP_LOCAL_CONNECT		16
#define E_PROXY				17
#define E_TCP_REMOTE_CONNECT		18
#define E_CONNECT			19
#define E_DELETE_SPAM			20
#define E_OPEN_USER_BLACK_LIST		21
#define E_LOGIN_CGI			22
#define E_IS_NOT_CGI			23
#define E_USERNAME_NOT_FOUND		24
#define E_INVALID_USERNAME_LEN		25
#define E_PASS_NOT_FOUND		26
#define E_INVALID_PASS_LEN		27
#define E_COOKIE_FILE_DOES_NOT_EXIST	28
#define E_SET_COOKIE			29
#define E_SAVING_CONF_FILE		30
#define E_AUTENTICATE_USER		31
#define E_OPEN_CONF_FILE		32
#define E_COOKIE_FILE_EXIST		33
#define E_OPEN_COOKIE_FILE		34
#define E_CREATE_RANDOM_STRING		35
#define E_CREATE_NEW_COOKIE_FILE	36
#define E_GET_COOKIE_VALUE		37
#define E_VALIDATE_COOKIE		38
#define E_SHOW_WELCOME_PAGE		39
#define E_SHOW_EDIT_BLACK_LIST_FORM_CGI 40
#define E_EDIT_BLACK_LIST_CGI		41
#define E_SHOW_MENU_CGI			42
#define E_GET_BLACK_LIST_DIR	43
#define E_LOGOUT_CGI			44


//====================================================================//
// Miscelanea 
//====================================================================//

/* End of string */
#define EOS	0


#endif /* _CONST_H_ */

/* $RCSfile: const.h,v $ */
