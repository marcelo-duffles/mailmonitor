//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: Secundary functions source file
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
 *  $Date: 2005/12/14 02:37:14 $
 *  
 *  $Log: functions.c,v $
 *  Revision 1.6  2005/12/14 02:37:14  marcelo
 *  sending() added
 *
 *  Revision 1.5  2005/12/14 02:21:05  marcelo
 *  New functions added
 *  Proxy() finished
 *
 *  Revision 1.4  2005/11/17 22:59:19  marcelo
 *  tcp_local_connect(), tcp_remote_connect() and proxy() added
 *
 *  Revision 1.3  2005/11/11 21:59:31  marcelo
 *  New functions source added
 *
 *  Revision 1.2  2005/11/10 23:07:44  marcelo
 *  usage() added
 *
 *       
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "config.h"
#include "const.h"
#include "functions.h"


/* Global variable which contains the error messages */
char *error_messages[] =
{
  /* 00 */ "Success.",
  /* 01 */ "Error while creating child process.",
  /* 02 */ "Error changing current directory.",
  /* 03 */ "Error closing standard files.",
  /* 04 */ "Error: log_msg()",
  /* 05 */ "Error: gethostname()",
  /* 06 */ "Error: gethostbyname()",
  /* 07 */ "Socket error",
  /* 08 */ "Error: bind()",
  /* 09 */ "Error: listen()",
  /* 10 */ "Error: sigaction()",
  /* 11 */ "Error: accept()",
  /* 12 */ "Error: send()",
  /* 13 */ "Error: invalid local POP3/SMTP port",
  /* 14 */ "Error: invalid POP3 server port",
  /* 15 */ "Error: recv()",
  /* 16 */ "Error: tcp_local_connect()",
  /* 17 */ "Error: proxy()",
  /* 18 */ "Error: tcp_remote_connect()",
  /* 19 */ "Error: connect()",
  /* 20 */ "Error: delete_spam()",
  /* 21 */ "Error opening user black list",
  /* 22 */ "Error: login CGI",
  /* 23 */ "Error: this is not a CGI",
  /* 24 */ "Error: username is missing",
  /* 25 */ "Error: invalid username length",
  /* 26 */ "Error: password is missing",
  /* 27 */ "Error: invalid password length",
  /* 28 */ "Error: cookie file does not exist",
  /* 29 */ "Error while setting cookie",
  /* 30 */ "Error while saving configuration file",
  /* 31 */ "Error: autenticateUser()",
  /* 32 */ "Error while opening configuration file",
  /* 33 */ "Error: cookieFileExist()",
  /* 34 */ "Error while opening cookie file",
  /* 35 */ "Error: createRandomString()",
  /* 36 */ "Error: createNewCookieFile()",
  /* 37 */ "Error: getCookieValue()",
  /* 38 */ "Error: validateCookie()",
  /* 39 */ "Error: showWelcomePage CGI",
  /* 40 */ "Error: showEditBlackListForm CGI",
  /* 41 */ "Error: editBlackList CGI",
  /* 42 */ "Error: showMenu CGI",
  /* 43 */ "Error: get_black_list_dir()",
  /* 44 */ "Error: logout CGI",
};

void usage (void)
{
  printf ("Usage: ./mailmonitor [-s|--smtp] -p|--port <POP3/SMTP port>\n\
                                 -A|--Address <POP3/SMTP server address>\n\
				 -P|--Port <POP3 server port>\n\
				 -d|--directory <black list directory>\n");
}

/* This function appends the 'filename' string to 'path'
 * and returns the result				*/
char *getLongFilename (char *path, char *filename)
{
  char *longFilename;
  
  if (path == NULL)
    return (NULL);
  if (filename == NULL)
    return (NULL);
           
  longFilename = (char *) malloc (strlen (path) + strlen (filename) +2);
  if (longFilename == NULL)
    return (NULL);
        
  strcpy (longFilename, path);
  if ((path[0] == EOS) || (path[strlen (path) -1] != '/'))
    strcat (longFilename, "/");
  strcat (longFilename, filename);
  
  return (longFilename);
}

int get_string (FILE *file, unsigned max_len, char *string)
{
  unsigned i;
  
  if ((file == NULL) || (string == NULL))
    return (ERROR);
  
  for (i = 0; i <= max_len; i++)
  {
    if ((fread (&string[i], 1, 1, file)) != 1)
    {
      if (ferror (file))
        return (ERROR);
      return (END_OF_FILE);
    }
    if (string[i] == '\n')
    {
      string[i] = EOS;
      return (OK);
    }
  }
  return (ERROR);
}

int put_string (FILE *file, char *string)
{
  unsigned i;
  char c = '\n';
  
  if ((file == NULL) || (string == NULL))
    return (ERROR);
  
  for (i = 0; i <= strlen (string); i++)
  {
    if (string[i] == EOS)
    {
      if ((fwrite (&c, 1, 1, file)) != 1)
      {
        if (ferror (file))
          return (ERROR);
        return (END_OF_FILE);
      }
      return (OK);
    }
    if ((fwrite (&string[i], 1, 1, file)) != 1)
    {
      if (ferror (file))
        return (ERROR);
      return (END_OF_FILE);
    }
  }
  return (ERROR);
}

/* Function to log messages in log file */
unsigned log_msg (char *message)
{
  FILE *log_file;
  time_t t;
  char *string;
    
  log_file = fopen (getLongFilename (DATA_DIR, LOG_FILE_NAME), "a+");
  if (log_file == NULL)
    return (EXIT_FAILURE);
  
  t = time (NULL);
  string = ctime (&t);
  string[strlen (string) -1] = EOS;
  
  if (message == NULL)
  {
    fprintf (log_file, "%s: %s\n", string, error_messages[E_LOG_MSG]);
    fclose (log_file);
    return (EXIT_FAILURE);
  }

  fprintf (log_file, "%s: %s\n", string, message);

  fclose (log_file);
  return (EXIT_FAILURE);
};

void sigchld_handler (int s)
{
  while (waitpid (-1, NULL, WNOHANG) > 0);
}

int sending (int socket, char *msg, int len, unsigned int flags)
{
  int ret;
  unsigned bytes_sent;
  char *buffer;
  
  buffer = (char *) calloc (len +1, sizeof (char));
  memcpy (&buffer[0], &msg[0], len);
  buffer[len] = EOS;
  
  for (bytes_sent = 0;;)
  {
    ret = send (socket, buffer, strlen (buffer), flags);
    if (ret == ERROR)
      return (ERROR);
    bytes_sent += ret;
    if (bytes_sent == len)
      break;
    strcpy (&buffer[0], &buffer[ret]);
  } 
  
  free (buffer);
  return (len);
}

int tcp_local_connect (int *sockfd, unsigned port)
{
  int		     ret;		/* returned value of functions	*/
  struct sockaddr_in addr;		/* host address information	*/
  int		     opt_val=1;		/* setsockopt() option value	*/

  if (sockfd == NULL)
    return (E_TCP_LOCAL_CONNECT);
    
  *sockfd = socket (PF_INET, SOCK_STREAM, 0);
  if (*sockfd == ERROR)
    return (E_SOCKET);

  ret = setsockopt (*sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (int));
  if (ret == ERROR)
    return (E_SOCKET);        
 
  addr.sin_family	= AF_INET;         
  addr.sin_port		= htons (port);    
  addr.sin_addr.s_addr	= INADDR_ANY;
  memset (&(addr.sin_zero), EOS, 8); 

  ret = bind (*sockfd, (struct sockaddr *) &addr, sizeof (struct sockaddr));
  if (ret == ERROR)
    return (E_BIND);
    
  return (OK);
}

int tcp_remote_connect (int *sockfd, unsigned remote_port,
			struct hostent *server_addr)
{
  int		     ret;		/* returned value of functions	*/
  struct sockaddr_in addr;		/* host address information	*/
  int		     opt_val=1;		/* setsockopt() option value	*/

  if ((sockfd == NULL) || (server_addr == NULL))
    return (E_TCP_REMOTE_CONNECT);
    
  *sockfd = socket (PF_INET, SOCK_STREAM, 0);
  if (*sockfd == ERROR)
    return (E_SOCKET);

  ret = setsockopt (*sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (int));
  if (ret == ERROR)
    return (E_SOCKET);        
 
  addr.sin_family = AF_INET;         
  addr.sin_port	  = htons (remote_port);    
  addr.sin_addr	  = *((struct in_addr *) server_addr->h_addr);
  memset (&(addr.sin_zero), EOS, 8); 

  ret = connect (*sockfd, (struct sockaddr *) &addr, sizeof (struct sockaddr));
  if (ret == ERROR)
    return (E_CONNECT);
    
  return (OK);
}

char *get_username (char *username, char *buffer)
{
  unsigned i;

  if ((buffer == NULL) || (username == NULL))
    return (NULL);

  for (i = 5; buffer[i] == ' '; i++);

  strcpy (&username[0], &buffer[i]);
  username[strlen (username) - 2] = EOS;

  return (username);
}

char is_in_header (char *header, char *spam_addr)
{
  unsigned i;
  
  for (i = 0; strncmp (&header[i], "From", 4); i++);
  
  for (i += 6; header[i] != '@'; i++)
    if (!strncmp (&header[i], &spam_addr[0], strlen (spam_addr)))
      return (1);
  i++;
  if (!strncmp (&header[i], &spam_addr[0], strlen (spam_addr)))
    return (1);      
    
  return (0);
}

int delete_msg (int server_fd, unsigned msg_nb)
{
  char buffer[MAX_BUF_LEN +1];
  char cmd[20];
  int ret;
  
  sprintf (cmd, "DELE %u\r\n", msg_nb);

  ret = sending (server_fd, cmd, strlen (cmd), 0);
  if (ret == ERROR)
    return (E_SEND);

  ret = recv (server_fd, buffer, MAX_BUF_LEN, 0);
  if (ret == ERROR)
    return (E_RECV);
    
  buffer[ret -2] = EOS;
  log_msg (buffer);
  
  return (OK);
}

int delete_spam (int server_fd, char *username, char *black_list_dir)
{
  FILE *file;
  char deleted_msg;
  char buffer[MAX_BUF_LEN +1];
  char header[10*MAX_BUF_LEN +1];
  char spam_addr[MAX_EMAIL_LEN +1];
  char cmd[20];
  int ret;
  unsigned i, nb_msg, header_len;

  if ((username == NULL) || (black_list_dir == NULL))
    return (E_DELETE_SPAM);

  ret = sending (server_fd, "STAT\r\n", 6, 0);
  if (ret == ERROR)
    return (E_SEND);

  ret = recv (server_fd, buffer, MAX_BUF_LEN, 0);
  if (ret == ERROR)
    return (E_RECV);

  if (strncmp (&buffer[0], "-ERR", 4))
    nb_msg = atoi (&buffer[4]);

  file = fopen (getLongFilename (black_list_dir, username), "r");
  if (file == NULL)
    return (E_OPEN_USER_BLACK_LIST);

  for (;;)
  {
    ret = get_string (file, MAX_EMAIL_LEN, spam_addr);
    
    if (ret == END_OF_FILE)
      break;
      
    if (ret == ERROR)
      return (ERROR);
      
    if (ret == OK)
    {
      for (i = 1; i <= nb_msg; i++)
      {
	sprintf (cmd, "TOP %u 0\r\n", i);

	ret = sending (server_fd, cmd, strlen (cmd), 0);
	if (ret == ERROR)
	  return (E_SEND);

	/* Getting message header */
	header[0] = EOS;
	do
	{
	  ret = recv (server_fd, buffer, MAX_BUF_LEN, 0);
	  if (ret == ERROR)
	    return (E_RECV);
	  buffer[ret] = EOS;
	  
	  deleted_msg = 0;
	  if (!strncmp (&buffer[0], "-ERR", 4))
	  {
	    deleted_msg = 1;
	    break;
	  }
	    
	  strcat (header, buffer);
	  header_len = strlen (header);

          if ((header_len >= 5) && (!strncmp (&header[header_len -5], "\r\n.\r\n", 5)))
	    break;
	}
        while (1);

	if ((!deleted_msg) && (is_in_header (&header[0], &spam_addr[0])))
	{
	 ret = delete_msg (server_fd, i);
	 if (ret != OK)
	   return (ret);
	}
      }
    }
  }
  fclose (file);

  return (OK);
}

int proxy (int *client_fd, struct hostent *server_addr, unsigned pop3_server_port,
	   char *black_list_dir)
{
  char	buffer[MAX_BUF_LEN +1];		/* buffer			*/
  char  username[MAX_USERNAME_LEN +1];	/* username			*/
  char  opt;				/* pop3 command			*/
  char  missing;			/* nb of missing terminations	*/
  int	server_fd;			/* server socket descriptor	*/
  int	ret;				/* returned value of functions	*/
  
  if ((client_fd == NULL) || (server_addr == NULL) || (black_list_dir == NULL))
    return (E_PROXY);
    
  /* Connecting to the POP3 server */
  ret = tcp_remote_connect (&server_fd, pop3_server_port, server_addr);
  if (ret != OK)
    return (ret);
    
  for (opt = NOOP, missing = 0;;)
  {
    do
    {
      ret = recv (server_fd, buffer, MAX_BUF_LEN, 0);
      if (ret == ERROR)
        log_msg (error_messages[E_RECV]);
	
      /* Making buffer a NULL-terminated string */
      buffer[ret] = EOS;
  
      ret = sending (*client_fd, buffer, strlen (buffer), 0);
      if (ret == ERROR)
        log_msg (error_messages[E_SEND]);

      if ((ret == 0) || (!strncmp (&buffer[0], "-ERR", 4)))
        break;
	
      if (opt == QUIT)
        break;

      if (missing == 1)
	if ((strlen (buffer) >= 1) && (!strncmp (&buffer[0], "\n", 1)))
	{
	  opt = NOOP;
	  missing   = 0;
	  break;
	}

      if (missing == 2)
	if ((strlen (buffer) >= 2) && (!strncmp (&buffer[0], "\r\n", 2)))
	{
	  opt = NOOP;
	  missing   = 0;
	  break;
	}	

      if (missing == 3)
	if ((strlen (buffer) >= 3) && (!strncmp (&buffer[0], ".\r\n", 3)))
	{
	  opt = NOOP;
	  missing   = 0;
	  break;
	}

      if (missing == 4)
	if ((strlen (buffer) >= 4) && (!strncmp (&buffer[0], "\n.\r\n", 1)))
	{
	  opt = NOOP;
	  missing   = 0;
	  break;
	}

      if ((strlen (buffer) >= 5) && (!strncmp (&buffer[ret-5], "\r\n.\r\n", 5)))
      {
        opt = NOOP;
	missing   = 0;
	break;
      }

      if ((strlen (buffer) >= 4) && (!strncmp (&buffer[ret-4], "\r\n.\r", 4)))
	missing = 1;
      if ((strlen (buffer) >= 3) && (!strncmp (&buffer[ret-3], "\r\n."  , 3)))
	missing = 2;
      if ((strlen (buffer) >= 2) && (!strncmp (&buffer[ret-2], "\r\n"   , 2)))
	missing = 3;
      if ((strlen (buffer) >= 1) && (!strncmp (&buffer[ret-1], "\r"     , 1)))
	missing = 4;
    }
    while (opt == MULTILINE);
    
    if (opt == QUIT)
      break;

    if (opt == PASS)
      if (strncmp (&buffer[0], "-ERR", 4))
      {
	/* Deleting SPAM... */
	ret = delete_spam (server_fd, username, black_list_dir);
	if (ret != OK)
	  log_msg (error_messages[ret]);
      }

    ret = recv (*client_fd, buffer, MAX_BUF_LEN, 0);
    if (ret == ERROR)
      log_msg (error_messages[E_RECV]);
	
    /* Making buffer a NULL-terminated string */
    buffer[ret] = EOS;
  
    ret = sending (server_fd, buffer, strlen (buffer), 0);
    if (ret == ERROR)
      log_msg (error_messages[E_SEND]);
    
    opt = NOOP;
    if ((!strncmp (buffer, "USER", 4)) || (!strncmp (buffer, "user", 4)))
    {
      opt = USER;
      get_username (&username[0], &buffer[0]);
    }
    if ((!strncmp (buffer, "QUIT", 4)) || (!strncmp (buffer, "quit", 4)))
      opt = QUIT; 
    if ((!strncmp (buffer, "PASS", 4)) || (!strncmp (buffer, "pass", 4)))
      opt = PASS;
    if ((!strncmp (buffer, "LIST", 4)) || (!strncmp (buffer, "list", 4)) ||
	(!strncmp (buffer, "RETR", 4)) || (!strncmp (buffer, "retr", 4)) ||
	(!strncmp (buffer, "UIDL", 4)) || (!strncmp (buffer, "uidl", 4)) ||
	(!strncmp (buffer, "TOP" , 3)) || (!strncmp (buffer, "top" , 3)))
      opt = MULTILINE;
  }

  close (server_fd);

  return (OK);
}

void showHtmlErrorPage (unsigned errorCode)
{
    printf ("<HTML>\n");
    printf ("  <HEAD>\n");
    printf ("    <TITLE>Mail Monitor - Error Page</TITLE>\n");
    printf ("  </HEAD>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"5\" COLOR = \"#FFFFFF\">MAIL MONITOR</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <CENTER><STRONG><FONT FACE = \"Courier New\" SIZE = \"4\" COLOR = \"#FFFFFF\">ERROR PAGE</FONT></STRONG><CENTER>\n");
    printf ("    <HR>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"LEFT\">\n");
    printf ("       Description of the error: \n");
    printf ("    </DIV>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"CENTER\">\n");
    printf ("      %s\n", error_messages[errorCode]);
    printf ("    </DIV>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"LEFT\">\n");
    printf ("       If you don't know how to solve it, please contact the administrator of the system.\n");
    printf ("    </DIV>\n");
    printf ("    <BR><BR><BR>\n");
    printf ("<P ALIGN=\"left\"><A HREF=\"javascript:window.history.go(-1)\" TARGET=\"_self\">GO BACK</a>\n");
    printf ("    <BR>\n");
    printf ("    <A HREF=\"%s\" TARGET=\"_top\">Go to login page</a></p>\n", HTML_WEB_DIR);
    printf ("    <HR>\n");
    printf ("    <DIV ALIGN = \"RIGHT\"><FONT FACE = \"Courier New\" SIZE = \"2\"><U>Author:</U>\n");
    printf ("    <I> Marcelo Duffles Donato Moreira\n");
    printf ("    <BR>\n");
    printf ("    Last update: 14/12/05</I></FONT>\n");
    printf ("    </DIV></FONT>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");
}

int autenticateUser (char *username, char *pass)
{
  int		 server_fd;			/* server socket descriptor    */
  int		 ret;				/* returned value of functions */
  unsigned	 pop3_server_port;		/* POP3 server port	       */
  struct hostent *server_addr;			/* POP3/SMTP server address    */
  char		 black_list_dir[MAX_BUF_LEN+1];	/* black list directory	       */
  char		 tmp[MAX_BUF_LEN+1];		/* temp variable	       */
  FILE		 *conf_file;			/* configuration file	       */

  if ((username == NULL) || (pass == NULL))
    return (E_AUTENTICATE_USER);

  conf_file = fopen (getLongFilename (DATA_DIR, CONF_FILE_NAME), "r");
  if (conf_file == NULL)
    return (E_OPEN_CONF_FILE);

  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);			/* POP3 server address */
  server_addr = gethostbyname (&tmp[0]);
  if (server_addr == NULL)
    return (E_GETHOSTBYNAME);

  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);			/* local port */

  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);			/* POP3 server port */
  pop3_server_port = strtol (&tmp[0], NULL, 10);

  get_string (conf_file, MAX_BUF_LEN, &black_list_dir[0]);	/* black list directory */
  fclose (conf_file);

  /* Connecting to the POP3 server */
  ret = tcp_remote_connect (&server_fd, pop3_server_port, server_addr);
  if (ret != OK)
    return (ret);

  sprintf (&tmp[0], "USER %s\r\n", username);
  ret = sending (server_fd, tmp , strlen (tmp), 0);
  if (ret == ERROR)
  {
    close (server_fd);
    return (E_SEND);
  }
  
  ret = recv (server_fd, tmp, MAX_BUF_LEN, 0);
  if (ret == ERROR)
  {
    close (server_fd);
    return (E_RECV);
  }
  tmp[ret] = EOS;

  if (!strncmp (&tmp[0], "-ERR", 4))
  {
    close (server_fd);
    return (E_USERNAME_NOT_FOUND);
  }
	
  sprintf (&tmp[0], "PASS %s\r\n", pass);
  ret = sending (server_fd, tmp , strlen (tmp), 0);
  if (ret == ERROR)
  {
    close (server_fd);
    return (E_SEND);
  } 
  
  ret = recv (server_fd, tmp, MAX_BUF_LEN, 0);
  if (ret == ERROR)
  {
    close (server_fd);
    return (E_RECV);
  }
  tmp[ret] = EOS;

  if (!strncmp (&tmp[0], "-ERR", 4))
  {
    close (server_fd);
    return (E_PASS_NOT_FOUND);  
  }
  
  close (server_fd);
  return (OK);
}

int cookieFileExist (char *username)
{
  char   *cookieFilename;
  FILE *cookieFile;
  
  if (username == NULL)
    return (E_COOKIE_FILE_EXIST);
  
  cookieFilename = getLongFilename (COOKIES_DIR, username);
  if (cookieFilename == NULL)
    return (E_COOKIE_FILE_EXIST); 
  
  if ((cookieFile = fopen (cookieFilename, "r")) == NULL)
  {
    if (errno != ENOENT)
      return (E_OPEN_COOKIE_FILE);
    return (E_COOKIE_FILE_DOES_NOT_EXIST);
  }
  fclose (cookieFile);

  return (OK);
}

int createRandomString (char *validCharacters, unsigned length, char *randomString)
{
  unsigned i;

  if ((randomString == NULL) || (validCharacters == NULL) || (validCharacters[0] == EOS))
    return (E_CREATE_RANDOM_STRING);
  
  srand ((unsigned) time (NULL));
  for (i = 0; i < length; i++)
    randomString[i] = validCharacters[rand() % strlen (validCharacters)];
  randomString[i] = EOS;
  
  return (OK);    
}

int createNewCookieFile (char *cookieName, char *cookieValue, time_t cookieExpiration, char *ip)
{
  FILE *cookieFile;
  unsigned ret;
  char *cookieFilename;
  
  if ((cookieName == NULL) || (cookieValue == NULL) || (ip == NULL))
    return (E_CREATE_NEW_COOKIE_FILE);
    
  cookieFilename = getLongFilename (COOKIES_DIR, cookieName);
  if (cookieFilename == NULL)
    return (E_CREATE_NEW_COOKIE_FILE); 
  
  if ((cookieFile = fopen (cookieFilename, "w")) == NULL)
    return (E_OPEN_COOKIE_FILE);

  ret = put_string (cookieFile, cookieValue);
  if (ret != OK)
  {
    fclose (cookieFile);
    return (ret);
  }
   
  if ((fwrite (&cookieExpiration, sizeof (time_t), 1, cookieFile)) != 1)
  {
    fclose (cookieFile);
    if (ferror (cookieFile))
      return (E_CREATE_NEW_COOKIE_FILE);
    return (END_OF_FILE);
  }
  
  ret = put_string (cookieFile, ip);
  if (ret != OK)
  {
    fclose (cookieFile);
    return (ret);
  }

  fclose (cookieFile);

  return (OK);
}

int getCookieValue (char *cookieName, char *cookieValue)
{
  FILE *cookieFile;
  unsigned ret;
  char *cookieFilename;
  
  if ((cookieName == NULL) || (cookieValue == NULL))
    return (E_GET_COOKIE_VALUE);
    
  cookieFilename = getLongFilename (COOKIES_DIR, cookieName);
  if (cookieFilename == NULL)
    return (E_GET_COOKIE_VALUE); 
  
  if ((cookieFile = fopen (cookieFilename, "r")) == NULL)
  {
    if (errno != ENOENT)
      return (E_OPEN_COOKIE_FILE);
    return (E_COOKIE_FILE_DOES_NOT_EXIST);
  }
    
  if ((ret = get_string (cookieFile, COOKIE_VALUE_LENGTH, cookieValue)) != OK)
    return (ret);
  fclose (cookieFile);
  
  return (OK);
}

int get_black_list_dir (char *black_list_dir)
{
  char       tmp[MAX_BUF_LEN+1];        /* temp variable           */
  FILE       *conf_file;            /* configuration file          */

  if (black_list_dir == NULL)
    return (E_GET_BLACK_LIST_DIR);

  conf_file = fopen (getLongFilename (DATA_DIR, CONF_FILE_NAME), "r");
  if (conf_file == NULL)
    return (E_OPEN_CONF_FILE);

  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);         /* POP3 server address */
  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);         /* local port */
  get_string (conf_file, MAX_BUF_LEN, &tmp[0]);         /* POP3 server port */
  get_string (conf_file, MAX_BUF_LEN, &black_list_dir[0]);  /* black list directory */
  fclose (conf_file);
											
  return (OK);
}

void showHtmlInitialPage (char *cookieName)
{
  printf ("<HTML>\n");
  printf ("  <HEAD>\n");
  printf ("    <TITLE>Mail Monitor - Initial Page</TITLE>\n");
  printf ("  </HEAD>\n");
  printf ("<FRAMESET COLS=\"26%%,74%%\">\n");
  printf ("<FRAME NAME=\"menu\" SRC=\"%s/showMenu.cgi?cookieName=%s\">\n", HTML_CGIS_DIR, cookieName);
  printf ("<FRAME NAME=\"main\" SRC=\"%s/showWelcomePage.cgi?cookieName=%s\">\n", HTML_CGIS_DIR, cookieName);
  printf ("</FRAMESET>\n");
  printf ("</HTML>\n");
}

int validateCookie (char *cookieName, char *cookieValue, char *ip)
{
  unsigned ret;
  char *cookieFilename;
  char cookieValueInFile[COOKIE_VALUE_LENGTH +1];
  char ipInFile[MAX_LENGTH_IP +1];
  time_t cookieExpiration;
  FILE *cookieFile;
  
  if ((cookieName == NULL) || (cookieValue == NULL) || (ip == NULL))
    return (E_VALIDATE_COOKIE);
  
  if ((cookieFilename = getLongFilename (COOKIES_DIR, cookieName)) == NULL)
    return (E_VALIDATE_COOKIE); 
  
  if ((cookieFile = fopen (cookieFilename, "r")) == NULL)
  {
    if (errno != ENOENT)
      return (E_OPEN_COOKIE_FILE);
    return (E_COOKIE_FILE_DOES_NOT_EXIST);
  }
  
  if ((ret = get_string (cookieFile, COOKIE_VALUE_LENGTH, cookieValueInFile)) != OK)
  {
    fclose (cookieFile);
    return (ret);
  }
  if (strcmp (cookieValue, cookieValueInFile))
  {
    fclose (cookieFile);
    return (E_VALIDATE_COOKIE);
  }
   
  if ((fread (&cookieExpiration, sizeof (time_t), 1, cookieFile)) != 1)
  {
    fclose (cookieFile);
    if (ferror (cookieFile))
      return (E_VALIDATE_COOKIE);
    return (END_OF_FILE);
  }
  if (cookieExpiration < time (NULL))
  {
    fclose (cookieFile);
    return (E_VALIDATE_COOKIE);
  }
  
  if ((ret = get_string (cookieFile, MAX_LENGTH_IP, ipInFile)) != OK)
  {
    fclose (cookieFile);
    return (ret);
  }
  if (strcmp (ip, ipInFile))
  {
    fclose (cookieFile);
    return (E_VALIDATE_COOKIE);
  }
  
  fclose (cookieFile);
  
  return (OK);
}

void showWebUserMenu (char *cookieName)
{
    printf ("<HTML>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"2\" COLOR = \"#FFFFFF\">MENU</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <TABLE BORDER=\"1\" ALIGN = \"CENTER\">\n");
    printf ("    <FONT SIZE=\"1\">\n");
    printf ("    <TR><TD><H6><A HREF=\"showEditBlackListForm.cgi?cookieName=%s\" TARGET=\"main\">Edit black list</A></TD></TR>\n", cookieName);
    printf ("    <TR><TD><H6><A HREF=\"logout.cgi?cookieName=%s\" TARGET=\"_top\">Logout</A></TD></TR>\n", cookieName);
    printf ("    </FONT></TABLE\n");
    printf ("    <HR>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");
}

void showHtmlWelcomePage (char *username)
{
    printf ("<HTML>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"5\" COLOR = \"#FFFFFF\">MAIL MONITOR</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <CENTER><STRONG><FONT FACE = \"Courier New\" SIZE = \"4\" COLOR = \"#FFFFFF\">INITIAL PAGE</FONT></STRONG><CENTER>\n");
    printf ("    <HR>\n");
    printf ("    <BR>\n");
    printf ("    <DIV ALIGN = \"CENTER\"><FONT SIZE=\"2\">\n");
    printf ("       <STRONG>Welcome %s!</STRONG>\n", username);
    printf ("    </DIV>\n");
    printf ("    <BR>\n");
    printf ("    <BR><BR><BR>\n");
    printf ("<P ALIGN=\"left\"><A HREF=\"javascript:window.history.go(-1)\" TARGET=\"_self\">GO BACK</a>\n");
    printf ("    <BR>\n");
    printf ("    <A HREF=\"%s\" TARGET=\"_top\">Go to login page</a></p>\n", HTML_WEB_DIR);
    printf ("    <HR>\n");
    printf ("    <DIV ALIGN = \"RIGHT\"><FONT FACE = \"Courier New\" SIZE = \"2\"><U>Author:</U>\n");
    printf ("    <I> Marcelo Duffles Donato Moreira\n");
    printf ("    <BR>\n");
    printf ("    Last update: 14/12/05</I></FONT>\n");
    printf ("    </DIV></FONT>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");
}

void showHtmlOKPage (void)
{
    printf ("<HTML>\n");
    printf ("  <HEAD>\n");
    printf ("    <TITLE>Mail Monitor - Confirmation Page</TITLE>\n");
    printf ("  </HEAD>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"6\" COLOR = \"#FFFFFF\">MAIL MONITOR</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <CENTER><STRONG><FONT FACE = \"Courier New\" SIZE = \"5\" COLOR = \"#FFFFFF\">CONFIRMATION PAGE</FONT></STRONG><CENTER>\n");
    printf ("    <HR>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"LEFT\">\n");
    printf ("       Result of the operation: \n");
    printf ("    </DIV>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"CENTER\">\n");
    printf ("      Operation done successfully.\n");
    printf ("    </DIV>\n");
    printf ("    <BR><BR><BR>\n");
    printf ("<P ALIGN=\"left\"><A HREF=\"javascript:window.history.go(-1)\" TARGET=\"_self\">GO BACK</a>\n");
    printf ("    <BR>\n");
    printf ("    <A HREF=\"%s\" TARGET=\"_top\">Go to login page</a></p>\n", HTML_WEB_DIR);
    printf ("    <HR>\n");
    printf ("    <DIV ALIGN = \"RIGHT\"><FONT FACE = \"Courier New\" SIZE = \"2\"><U>Author:</U>\n");
    printf ("    <I> Marcelo Duffles Donato Moreira\n");
    printf ("    <BR>\n");
    printf ("    Last update: 14/12/05</I></FONT>\n");
    printf ("    </DIV></FONT>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");
}

/* $RCSfile: functions.c,v $ */
