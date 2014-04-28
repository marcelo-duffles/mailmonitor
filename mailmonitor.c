//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: Main program source file
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
 *  $Date: 2005/12/14 01:50:42 $
 *  
 *  $Log: mailmonitor.c,v $
 *  Revision 1.5  2005/12/14 01:50:42  marcelo
 *  Main loop finished
 *
 *  Revision 1.4  2005/11/17 23:28:14  marcelo
 *  Big Loop added
 *  Next step: improve proxy() function
 *
 *  Revision 1.3  2005/11/11 21:48:04  marcelo
 *  POP3 server initialization have been made
 *  Next step: fill variables with argument's data
 *
 *  Revision 1.2  2005/11/10 23:06:36  marcelo
 *  Added options handling
 *
 *  Revision 1.1  2005/11/09 19:17:34  marcelo
 *  Initial revision
 *       
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>

#include "const.h"
#include "functions.h"

static const char rcsid[] = "$Id: mailmonitor.c,v 1.5 2005/12/14 01:50:42 marcelo Exp marcelo $";

int main (int argc, char **argv)
{
  unsigned	     nb_options;	/* number of options		*/
  unsigned	     local_port;	/* local POP3/SMTP port		*/
  unsigned	     pop3_server_port;	/* POP3 server port		*/
  char		     tmp[MAX_BUF_LEN+1];/* temp variable		*/
  char		     *black_list_dir;	/* black list directory		*/
  char		     *endptr[10];	/* used by strtol()		*/
  char		     option;		/* command line option		*/
  char		     is_smtp_server=0;	/* boolean			*/
  int		     ret;		/* returned value of functions	*/
  int		     sockfd;		/* socket file descriptor	*/
  int		     client_fd;		/* client socket descriptor	*/
  pid_t		     child_pid;		/* child process ID		*/
  pid_t		     child_sid;		/* child process session ID	*/
  FILE		     *log_file;		/* log file			*/
  FILE		     *conf_file;	/* configuration file		*/
  struct hostent     *server_addr;	/* POP3/SMTP server address	*/
  struct sockaddr_in client_addr;	/* client address information	*/
  struct sigaction   sa;		/* sigaction structure		*/
  socklen_t	     sin_size;		/* socket length		*/

  /* string of short options */
  char string_options[] = "p:A:P:d:s";

  /* structure of long options */
  static struct option options[] = 
  {
    {"port",	  1, 0, 'p'},
    {"Address",   1, 0, 'A'},
    {"Port",	  1, 0, 'P'},
    {"directory", 1, 0, 'd'},
    {"smtp",	  0, 0, 's'},
    {0, 0, 0, 0}
  };
  
  
  //====================================================================//
  // Getting program options
  //====================================================================//

  if ((argc != MIN_NB_ARGS) && (argc != MAX_NB_ARGS))
  {
    usage();
    exit (EXIT_FAILURE);
  }

  for (opterr = 0, nb_options = 0; ; nb_options++)
  {
    option = getopt_long (argc, argv, string_options, options, NULL);

    if (option == EOF)
      break;

    if ((optarg != NULL) && (optarg[0] == '-'))
    {
      usage();
      exit (EXIT_FAILURE);
    }

    switch (option)
    {
      case 'p':
        local_port = strtol (optarg, &endptr[0], 10);
	if ((local_port == 0) || (*endptr[0] != EOS))
	  exit (log_msg (error_messages[E_INVAL_LOCAL_PORT]));
      break;

      case 'A':
	strcpy (&tmp[0], optarg);
	server_addr = gethostbyname (optarg);
	if (server_addr == NULL)
	  exit (log_msg (error_messages[E_GETHOSTBYNAME]));
      break;

      case 'P':
        pop3_server_port = strtol (optarg, &endptr[0], 10);
	if ((pop3_server_port == 0) || (*endptr[0] != EOS))
	  exit (log_msg (error_messages[E_INVAL_POP3_SERVER_PORT]));
      break;

      case 'd':
	black_list_dir = (char *) calloc (strlen (optarg) +1, sizeof (char));
	strcpy (black_list_dir, optarg);
      break;

      case 's':
        if ((optarg != NULL) && (optarg[0] != '-'))
	{
          usage();
          exit (EXIT_FAILURE);
	}
	is_smtp_server = 1;
      break;

      default:
        usage();
        exit (EXIT_FAILURE);
    }
  }

  if ((nb_options != MIN_NB_OPTIONS) && (nb_options != MAX_NB_OPTIONS))
  {
    usage();
    exit (EXIT_FAILURE);
  }


  //====================================================================//
  // Initializing Daemon
  //====================================================================//
  
  /* Creating child process */
  child_pid = fork();
  if (child_pid == ERROR)
    exit (EXIT_FAILURE);

  /* Leaving the parent process */
  if (child_pid > 0)
    exit (EXIT_SUCCESS);

  /* Setting file creation mode mask */
  umask (0);
  
  /* Creating log file */
  log_file = fopen (getLongFilename (DATA_DIR, LOG_FILE_NAME), "a");
  if (log_file == NULL)
    exit (EXIT_FAILURE);
  fclose (log_file);
  
  /* Creating a new session for the child process */
  child_sid = setsid ();
  if (child_sid == ERROR)
    exit (log_msg (error_messages[E_CREATING_CHILD_SESSION]));

  /* Changing the current working directory */
  if (chdir("/"))
    exit (log_msg (error_messages[E_CHANGING_DIRECTORY]));

  /* Closing out the standard file descriptors */
//  if (close(STDIN_FILENO))
//    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));
//  if (close(STDOUT_FILENO))
//    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));
//  if (close(STDERR_FILENO))
//    exit (log_msg (error_messages[E_CLOSING_STANDARD_FILES]));

  sa.sa_handler = sigchld_handler; /* reap all dead processes */
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  ret = sigaction (SIGCHLD, &sa, NULL);
  if (ret == ERROR)
    exit (log_msg (error_messages[E_SIGACTION]));
  
  /* Saving configuration data */
  conf_file = fopen (getLongFilename (DATA_DIR, CONF_FILE_NAME), "w");
  if (conf_file == NULL)
    exit (log_msg (error_messages[E_SAVING_CONF_FILE]));
  put_string (conf_file, &tmp[0]);		/* POP3 server address */
  sprintf (&tmp[0], "%u", local_port);
  put_string (conf_file, &tmp[0]);		/* local port */
  sprintf (&tmp[0], "%u", pop3_server_port);
  put_string (conf_file, &tmp[0]);		/* POP3 server port */
  put_string (conf_file, black_list_dir);	/* black list directory */
  fclose (conf_file);


  //====================================================================//
  // Initializing (local) POP3 server
  //====================================================================//
     
  ret = tcp_local_connect (&sockfd, local_port);
  if (ret != OK)
    exit (log_msg (error_messages[ret]));
    
  ret = listen (sockfd, MAX_CONNECTIONS);
  if (ret == ERROR)
    exit (log_msg (error_messages[E_LISTEN]));
    
      
  //====================================================================//
  // The Main Loop
  //====================================================================//
  
  while (1)
  {  
    sin_size = sizeof (struct sockaddr_in);
    
    /* Accepting incoming connection from client */
    client_fd = accept (sockfd, (struct sockaddr *) &client_addr, &sin_size);
    if (client_fd == ERROR)
    {
      log_msg (error_messages[E_ACCEPT]);
      continue;
    }

    if (!fork())
    { 
      /* Closing parent socket file descriptor */
      close (sockfd); 

      /* Starting to proxy */
      ret = proxy (&client_fd, server_addr, pop3_server_port, black_list_dir);
      if (ret != OK)
        log_msg (error_messages[ret]);

      /* Closing child socket file descriptor */
      close (client_fd); 
      
      /* Exiting client process */
      exit (EXIT_SUCCESS);
    }

    /* Closing child socket file descriptor */
    close (client_fd); 
  }

  exit (EXIT_SUCCESS);
}

/* $RCSfile: mailmonitor.c,v $ */
