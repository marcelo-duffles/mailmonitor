//===========================================================================//
// Universidade Federal do Rio de Janeiro
// Escola Politécnica
// Departamento de Eletrônica e de Computação
// Professor Marcelo Luiz Drumond Lanza
// Internet and TCP/IP Architecture
// Author: Marcelo Duffles Donato Moreira <marcelo@gta.ufrj.br>
// Description: showEditBlackListForm CGI source file
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
 * $Date: 2005/12/23 18:09:00 $
 * 
 * $Log: showEditBlackListForm.c,v $
 * Revision 1.1  2005/12/23 18:09:00  marceloddm
 * Initial revision
 *
 *
 */



#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "mlcgi.h"
#include "const.h"
#include "config.h"
#include "functions.h"


static const char rcsid [] = "$Id: showEditBlackListForm.c,v 1.1 2005/12/23 18:09:00 marceloddm Exp marceloddm $";


int main (int argc, char **argv)
{
  unsigned ret;	
  char new_file = 0;
  char cookieName[COOKIE_NAME_LENGTH +1];
  char cookieValue[COOKIE_VALUE_LENGTH +1];
  char *cookieFileName;
  char black_list[50*MAX_EMAIL_LEN +1];
  char black_list_dir[100 +1];
  char buffer[MAX_EMAIL_LEN +1];
  FILE *file;
  unsigned len;

  if ((ret = mlCgiInitialize ()) != ML_CGI_OK)
  {
    showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
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
    showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
    exit (ML_CGI_OK);
  }

  if ((ret = mlCgiGetSpecificCookie (cookieName, COOKIE_NAME_LENGTH, cookieValue, COOKIE_VALUE_LENGTH)) != ML_CGI_OK)
  {
    mlCgiEndHttpHeader();
    mlCgiFreeResources ();
    showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
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
        showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
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


  ret = get_black_list_dir (&black_list_dir[0]);
  if (ret != OK)
  {
    showHtmlErrorPage (ret);
    exit (ML_CGI_OK);
  }
  
  log_msg (&black_list_dir[0]);

  file = fopen (getLongFilename (&black_list_dir[0], cookieName), "r");
  if (file == NULL)
  {
	if (errno == ENOENT)
	{
	  file = fopen (getLongFilename (&black_list_dir[0], cookieName), "w");
	  if (file == NULL)
	  {
        showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
        exit (ML_CGI_OK);
	  }
	  new_file = 1;
	}
	else
	{
      showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
      exit (ML_CGI_OK);
	}
  }

  black_list[0] = EOS;
  do
  {
	if (new_file)
	  break;
    ret = get_string (file, MAX_EMAIL_LEN, &buffer[0]);
    if (ret == END_OF_FILE)
      break;
    if (ret != OK)
    {
      showHtmlErrorPage (E_SHOW_EDIT_BLACK_LIST_FORM_CGI);
      exit (ML_CGI_OK);
    }
    len = strlen (buffer);
    buffer[len]   = '\n';
    buffer[len+1] = EOS;
    strcat (&black_list[0], &buffer[0]);
  }
  while (1);
  
    printf ("<HTML>\n");
    printf ("  <HEAD>\n");
    printf ("    <TITLE>Mail Monitor - Form to edit black list</TITLE>\n");
    printf ("  </HEAD>\n");
    printf ("  <BODY BACKGROUND = \"%s/zertxtr.gif\" BGCOLOR = \"#000000\" TEXT = \"#FFFFFF\" LINK = \"#6699CC\" VLINK = \"#669966\" ALINK = \"#999999\">\n", HTML_IMAGES_DIR);
    printf ("    <DIV ALIGN = \"CENTER\"><STRONG><FONT FACE = \"Courier New\" SIZE = \"5\" COLOR = \"#FFFFFF\">MAIL MONITOR</FONT></STRONG></DIV>\n");
    printf ("    <HR>\n");
    printf ("    <CENTER><STRONG><FONT FACE = \"Courier New\" SIZE = \"4\" COLOR = \"#FFFFFF\">FORM TO EDIT BLACK LIST</FONT></STRONG><CENTER>\n");
    printf ("    <HR>\n");
    printf ("    <BR>\n");
    printf ("    <DIV ALIGN = \"CENTER\"><FONT SIZE=\"2\">\n");
    printf ("       <I>Enter spam addresses.\n");
    printf ("    <BR>\n");
    printf ("          Only one address in each line.</I>\n");
    printf ("    </DIV>\n");
    printf ("    <BR>\n");
    printf ("    <TABLE BORDER=\"1\" ALIGN = \"center\">\n");
    printf ("    <FORM ACTION=\"%s/editBlackList.cgi\" METHOD=\"post\">\n", HTML_CGIS_DIR);
    printf ("                      <INPUT TYPE=\"hidden\"   NAME=\"cookieName\" VALUE=\"%s\">\n", cookieName);
    printf ("       <TR><TD><TEXTAREA NAME=\"black_list\" ROWS=\"20\" COLS=\"60\">%s</TEXTAREA></TD></TR>\n", &black_list[0]);
    printf ("    </TABLE>\n");  	
    printf ("    <BR><BR>\n");
    printf ("                      <INPUT TYPE=\"submit\"   VALUE=\"Submit\">\n");
    printf ("                      <INPUT TYPE=\"reset\"    VALUE=\"Clear\">\n");
    printf ("    </FORM>\n");
    printf ("    <BR><BR><BR>\n");
    printf ("<P ALIGN=\"left\"><A HREF=\"javascript:window.history.go(-1)\" TARGET=\"_self\">GO BACK</a></p>\n");
    printf ("    <HR>\n");
    printf ("    <DIV ALIGN = \"RIGHT\"><FONT FACE = \"Courier New\" SIZE = \"2\"><U>Author:</U>\n");
    printf ("    <I> Marcelo Duffles Donato Moreira\n");
    printf ("    <BR>\n");
    printf ("    Last update: 14/12/05</I></FONT>\n");
    printf ("    </DIV></FONT>\n");
    printf ("  <BODY>\n");
    printf ("</HTML>\n");

  exit (ML_CGI_OK);
}

/*$RCS$*/
