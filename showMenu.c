//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: showMenu CGI source file
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
 * $Date: 2005/12/23 18:09:46 $
 * 
 * $Log: showMenu.c,v $
 * Revision 1.1  2005/12/23 18:09:46  marceloddm
 * Initial revision
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include "mlcgi.h"
#include "const.h"
#include "config.h"
#include "functions.h"


static const char rcsid [] = "$Id: showMenu.c,v 1.1 2005/12/23 18:09:46 marceloddm Exp marceloddm $";


int main (int argc, char **argv)
{
  unsigned ret;	
  char cookieName[COOKIE_NAME_LENGTH +1];
  char cookieValue[COOKIE_VALUE_LENGTH +1];
  char *cookieFileName;

  if ((ret = mlCgiInitialize ()) != ML_CGI_OK)
  {
    showHtmlErrorPage (E_SHOW_MENU_CGI);
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
    showHtmlErrorPage (E_SHOW_MENU_CGI);
    exit (ML_CGI_OK);
  }

  if ((ret = mlCgiGetSpecificCookie (cookieName, COOKIE_NAME_LENGTH, cookieValue, COOKIE_VALUE_LENGTH)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_SHOW_MENU_CGI);
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
      cookieFileName = getLongFilename (COOKIES_DIR, cookieName);
      if (cookieFileName == NULL)
      {
        mlCgiEndHttpHeader();
        mlCgiFreeResources ();
        showHtmlErrorPage (E_SHOW_MENU_CGI);
        exit (ML_CGI_OK); 
      }
      remove (cookieFileName); 
    }
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (ret);
    exit (ML_CGI_OK); 
  }

  mlCgiEndHttpHeader();
  mlCgiFreeResources ();
  
  showWebUserMenu (cookieName);

  exit (ML_CGI_OK);
}

/* $RCSfile: showMenu.c,v $ */
