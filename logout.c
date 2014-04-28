//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: Logout CGI source file
// Date: 23/12/2005
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
 * $Date: 2005/12/23 18:08:35 $
 * 
 * $Log: logout.c,v $
 * Revision 1.1  2005/12/23 18:08:35  marceloddm
 * Initial revision
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "mlcgi.h"
#include "const.h"
#include "config.h"
#include "functions.h"


static const char rcsid [] = "$Id: logout.c,v 1.1 2005/12/23 18:08:35 marceloddm Exp marceloddm $";


int main (int argc, char **argv)
{
  int ret;	
  char cookieName[MAX_USERNAME_LEN +1];
  char cookieValue[COOKIE_VALUE_LENGTH +1];
  char *cookieFileName;

  if ((ret = mlCgiInitialize ()) != ML_CGI_OK)
  {
    showHtmlErrorPage (E_LOGOUT_CGI);
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
    showHtmlErrorPage (E_LOGOUT_CGI);
    exit (ML_CGI_OK);
  }

  if ((ret = mlCgiGetSpecificCookie (cookieName, COOKIE_NAME_LENGTH, cookieValue, COOKIE_VALUE_LENGTH)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_LOGOUT_CGI);
    exit (ML_CGI_OK); 
  }

  if ((ret = mlCgiSetCookie (cookieName, cookieValue, 0, NULL, NULL, NULL)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_LOGOUT_CGI);
    exit (ML_CGI_OK); 
  }
  if ((cookieFileName = getLongFilename (COOKIES_DIR, cookieName)) == NULL)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_LOGOUT_CGI);
    exit (ML_CGI_OK); 
  }
  remove (cookieFileName); 
  
  mlCgiEndHttpHeader();
  mlCgiFreeResources ();
  
    printf ("<HTML>\n");
    printf ("  <HEAD>\n");
    printf ("    <TITLE>Mail Monitor - Logout Page</TITLE>\n");
    printf ("  </HEAD>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"6\" COLOR = \"#FFFFFF\">MAIL MONITOR</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <CENTER><STRONG><FONT FACE = \"Courier New\" SIZE = \"5\" COLOR = \"#FFFFFF\">LOGOUT PAGE</FONT></STRONG><CENTER>\n");
    printf ("    <HR>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"center\">\n");
    printf ("      You have logout successfully.\n");
    printf ("    </DIV>\n");
    printf ("    <BR><BR>\n");
    printf ("    <DIV ALIGN = \"CENTER\">\n");
    printf ("      Thank you for join our system!<BR><BR><BR>\n");
    printf ("    <A HREF=\"%s\" TARGET=\"_top\">Go to login page</a>\n", HTML_WEB_DIR);
    printf ("    </DIV>\n");
    printf ("    <BR><BR>\n");
    printf ("    <BR><BR><BR>\n");
    printf ("<P ALIGN=\"left\"><A HREF=\"javascript:window.history.go(-1)\" TARGET=\"_self\">GO BACK</A></p>\n");
    printf ("    <HR>\n");
    printf ("    <DIV ALIGN = \"RIGHT\"><FONT FACE = \"Courier New\" SIZE = \"2\"><U>Author:</U>\n");
    printf ("    <I> Marcelo Duffles Donato Moreira\n");
    printf ("    <BR>\n");
    printf ("    Last update: 23/12/05</I></FONT>\n");
    printf ("    </DIV></FONT>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");

  exit (ML_CGI_OK);
}

/*$RCSfile: logout.c,v $*/
