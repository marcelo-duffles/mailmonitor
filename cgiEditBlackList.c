//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: editBlackList CGI source file
// Date: 14/12/2005
//===========================================================================//
//
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
 * RCS COMMENTS
 *
 * $Author: marceloddm $
 * $Date: 2005/12/23 18:10:34 $
 * 
 * $Log: cgiEditBlackList.c,v $
 * Revision 1.1  2005/12/23 18:10:34  marceloddm
 * Initial revision
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mlcgi.h"
#include "const.h"
#include "config.h"
#include "functions.h"

static const char rcsid [] = "$Id: cgiEditBlackList.c,v 1.1 2005/12/23 18:10:34 marceloddm Exp marceloddm $";


int main (int argc, char **argv)
{
  unsigned ret;	
  char oldCookieName[COOKIE_NAME_LENGTH +4 +1];
  char cookieName[COOKIE_NAME_LENGTH +1];
  char cookieValue[COOKIE_VALUE_LENGTH +1];
  char *cookieFileName;
  char *new_name;
  char *old_name;
  char black_list[50*MAX_EMAIL_LEN +1];
  char temp[50*MAX_EMAIL_LEN +1];
  char buffer[MAX_EMAIL_LEN +1];
  char black_list_dir[100 +1];
  FILE *file;
  unsigned i;


  if ((ret = mlCgiInitialize ()) != ML_CGI_OK)
  {
    showHtmlErrorPage (E_EDIT_BLACK_LIST_CGI);
    exit (ML_CGI_OK);
  }

  if (!isCgi)
  {
    log_msg (error_messages[E_IS_NOT_CGI]);
    exit (ML_CGI_OK);
  }
	  
  mlCgiBeginHttpHeader ("text/html");
    
  if ((ret = mlCgiGetFormStringNoNewLines ("cookieName", cookieName, COOKIE_NAME_LENGTH)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader ();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_EDIT_BLACK_LIST_CGI);
    exit (ML_CGI_OK);
  }

  if ((ret = mlCgiGetSpecificCookie (cookieName, COOKIE_NAME_LENGTH, cookieValue, COOKIE_VALUE_LENGTH)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_EDIT_BLACK_LIST_CGI);
    exit (ML_CGI_OK); 
  }
  
  if ((ret = validateCookie (cookieName, cookieValue, mlCgiEnvironmentVariablesValues[ML_CGI_REMOTE_ADDRESS])) != OK)
  {
    if (ret != E_COOKIE_FILE_DOES_NOT_EXIST)
    {
      if ((ret = getCookieValue (cookieName, cookieValue)) != OK)
      {
        mlCgiEndHttpHeader ();
        mlCgiFreeResources ();
        showHtmlErrorPage (ret);
        exit (ML_CGI_OK);
      }
      if ((ret = mlCgiSetCookie (cookieName, cookieValue, 0, NULL, NULL, NULL)) != ML_CGI_OK)
      {
        mlCgiEndHttpHeader();
        mlCgiFreeResources ();
        showHtmlErrorPage (E_SET_COOKIE);
        exit (ML_CGI_OK); 
      }
      if ((cookieFileName = getLongFilename (COOKIES_DIR, cookieName)) == NULL)
      {
        mlCgiEndHttpHeader();
        mlCgiFreeResources ();
        showHtmlErrorPage (E_EDIT_BLACK_LIST_CGI);
        exit (ML_CGI_OK); 
      }
      remove (cookieFileName); 
    }
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (ret);
    exit (ML_CGI_OK); 
  }

  if ((ret = mlCgiGetFormStringNoNewLines ("black_list", &black_list[0], 50*MAX_EMAIL_LEN)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader ();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_EDIT_BLACK_LIST_CGI);
    exit (ML_CGI_OK);
  }

  mlCgiEndHttpHeader();
  mlCgiFreeResources ();

  ret = get_black_list_dir (&black_list_dir[0]);
  if (ret != OK)
  {
    showHtmlErrorPage (ret);
    exit (ML_CGI_OK);
  }

  new_name = getLongFilename (&black_list_dir[0], cookieName);
  sprintf (&oldCookieName[0], "%s.old", cookieName);
  old_name = getLongFilename (&black_list_dir[0], oldCookieName);
  rename (new_name, old_name);

  file = fopen (new_name, "w");
  if (file == NULL)
  {
    showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
    exit (ML_CGI_OK);
  }

  do
  {
    if (black_list[0] == EOS)
      break;

    for (i = 0; black_list[i] != '\n'; i++)
      buffer[i] = black_list[i];
    buffer[i] = EOS;

    temp[0] = EOS;
    strcpy (&temp[0], &black_list[i+1]);
    strcpy (&black_list[0], &temp[0]);
    
    ret = put_string (file, &buffer[0]);
    if (ret != OK)
    {
      showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
      exit (ML_CGI_OK);
    }
  }
  while (1);


  showHtmlOKPage ();

  exit (ML_CGI_OK);
}

/*$RCSfile: cgiEditBlackList.c,v $*/
