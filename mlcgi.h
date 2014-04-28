/*
 * Universidade do Brasil
 * Escola Politecnica
 * Departamento de Eletronica e Computacao
 * Computacao II
 * Prof. Marcelo Luiz Drumond Lanza
 *
 * File:                mlcgi.h
 * Author:              Marcelo Luiz Drumond Lanza
 * Description:         This file includes global constants, extern variables
 *                      and function prototypes used for helping in CGI
 *                      creation.
 * $Date: 2005/02/16 22:11:21 $
 * $Log: mlcgi.h,v $
 * Revision 1.1  2005/02/16 22:11:21  marceloddm
 * Initial revision
 *
 * Revision 1.4  2001/06/17 01:37:13  lanza
 * Included cookie
 *
 * Revision 1.3  2001/06/16 05:08:06  lanza
 * Generic environment variables
 *
 */

#ifndef __ML_CGI_H__
#define __ML_CGI_H__ "@(#)mlcgi.h $Revision: 1.1 $"

/* Constants */
#define ML_CGI_FALSE                                    0
#define ML_CGI_TRUE                                     1

#define ML_CGI_MAX_COOKIE_NAME_LENGTH			1024

/* Global Types */
typedef enum {Netscape, Explorer, Lynx} browserType;

/* Global Variables */
extern unsigned isCgi;
/*
 *  	ML_CGI_TRUE if this program is executed as a CGI
 *      ML_CGI_FALSE if this program is executed as a line command
 */

extern browserType browser;
/*
 *      Netscape, Explorer, Lynx
 */

#ifdef __ML_CGI_GLOBAL_VARIABLES__

typedef enum
{
  ML_CGI_SERVER_SOFTWARE,
  ML_CGI_SERVER_NAME,
  ML_CGI_SERVER_PROTOCOL,
  ML_CGI_SERVER_PORT,
  ML_CGI_SERVER_ADDRESS,
  ML_CGI_SERVER_ADMIN,
  ML_CGI_SERVER_SIGNATURE,
  ML_CGI_DOCUMENT_ROOT,
  ML_CGI_GATEWAY_INTERFACE,
  ML_CGI_REQUEST_METHOD,
  ML_CGI_REQUEST_URL,
  ML_CGI_PATH_INFO,
  ML_CGI_PATH_TRANSLATED,
  ML_CGI_SCRIPT_FILENAME,
  ML_CGI_SCRIPT_NAME,
  ML_CGI_QUERY_STRING,
  ML_CGI_AUTH_TYPE,
  ML_CGI_REMOTE_HOST,
  ML_CGI_REMOTE_ADDRESS,
  ML_CGI_REMOTE_PORT,
  ML_CGI_REMOTE_USER,
  ML_CGI_REMOTE_IDENTITY,
  ML_CGI_CONTENT_TYPE,
  ML_CGI_CONTENT_LENGTH,
  ML_CGI_HTTP_ACCEPT,
  ML_CGI_HTTP_ACCEPT_CHARSET,
  ML_CGI_HTTP_ACCEPT_ENCODING,
  ML_CGI_HTTP_ACCEPT_LANGUAGE,
  ML_CGI_HTTP_USER_AGENT,
  ML_CGI_HTTP_REFERER,
  ML_CGI_HTTP_HOST,
  ML_CGI_HTTP_CONNECTION,
  ML_CGI_HTTP_COOKIE,
  ML_CGI_PATH
} mlCgiEnvironmentVariablesConstantes;

#define ML_CGI_ENVIRONMENT_VARIABLES_AMOUNT ML_CGI_PATH + 1

extern char *mlCgiEnvironmentVariablesStrings [];
extern char *mlCgiEnvironmentVariablesValues [];
extern int mlCgiContentLength;

#endif


typedef enum
{
  ML_CGI_OK,
  ML_CGI_FATAL_ERROR,
  ML_CGI_MEMORY_ALLOCATION_ERROR,
  ML_CGI_IO_ERROR,
  ML_CGI_INVALID_CONTENT_LENGTH,
  ML_CGI_INVALID_CONTENT_TYPE,
  ML_CGI_INVALID_REQUEST_METHOD,
  ML_CGI_FORM_FIELD_NOT_FOUND,
  ML_CGI_INVALID_FORM_LENGTH,
  ML_CGI_INVALID_COOKIE_NAME,
  ML_CGI_INVALID_COOKIE_VALUE,
  ML_CGI_INVALID_COOKIE_EXPIRATION,
  ML_CGI_INVALID_COOKIE_PATH,
  ML_CGI_INVALID_COOKIE_DOMAIN,
  ML_CGI_INVALID_COOKIE_SECURITY,
  ML_CGI_INVALID_COOKIE_NAME_LENGTH,
  ML_CGI_COOKIE_NOT_FOUND
} mlCgiErrorConstants;

extern char *mlCgiHtmlErrorMessages [];
extern char *mlCgiTextErrorMessages [];

/*---------------------------------------------------------------------------*/
/*
 *      Initialize the CGI library variables. Check if the program is running
 *      as a line command or as a CGI. If it runs as line command, sets the
 *      variable isCgi to ML_CGI_FALSE. Otherwise, it sets this variable to
 *      ML_CGI_TRUE.
 *      This is the first function to be executed.
 *
 * Returned Value:
 *      ML_CGI_OK if this function is successfully executed or if it is a
 *      line command. If an error takes place, returns one of the following
 *      error constants:
 *      ML_CGI_FATAL_ERROR
 *      ML_CGI_MEMORY_ALLOCATION_ERROR
 *      ML_CGI_IO_ERROR
 *      ML_CGI_INVALID_CONTENT_LENGTH
 *      ML_CGI_INVALID_CONTENT_TYPE
 *      ML_CGI_INVALID_REQUEST_METHOD
 */
unsigned mlCgiInitialize (void);


/*---------------------------------------------------------------------------*/
/*
 *      Free all allocated memory.
 *
 */
void mlCgiFreeResources (void);


/*---------------------------------------------------------------------------*/
/*
 *      Send the content type to the client browser.
 *
 * Arguments:
 *      char * - content type value: NULL or a valid content type
 *      ("text/html").
 */
void mlCgiBeginHttpHeader (char *);

/*---------------------------------------------------------------------------*/
/*
 *      Send a blank line to client browser: end of HTTP header.
 */
void mlCgiEndHttpHeader (void);


/*---------------------------------------------------------------------------*//*
 *      Get the value for a form text field
 *
 * Argumentos:
 *      char * - field name
 *      char * - field value
 *      int    - field value length
 *
 * Retorna:
 *      ML_CGI_OK if a field with fieldName has been semt from client to server.
 *      Otherwise, returns ML_CGI_FORM_NOT_FOUND or ML_CGI_INVALID_FORM_LENGTH
 *
 */
unsigned mlCgiGetFormStringNoNewLines (char *, char *, unsigned);

/*---------------------------------------------------------------------------*/
/*
 *      Send a cookie to the client browser. It should be called
 *      between mlCgiBeginHttpHeader and mlCgiEndHttpHeader.
 *
 * Arguments:
 *      char * - cookie name
 *              (should be not NULL ou a string with null length)
 *      char * - cookie value
 *              (should be not NULL ou a string with null length)
 *      unsigned long - cookie expiration
 *              (with format "Mon, 01-Jan-2001 00:00:00 GMT")
 *      char * - cookie path attributes, p. ex., "/home/www"
 *              (can be NULL or a string with null length)
 *      char * - cookie domain, p. ex., "www.mydomain.com"
 *              (can be NULL or a string with null length)
 *      char * - cookie security attributes
 *              (can be NULL or true or false)
 *
 * Retuned Values:
 *      ML_CGI_OK or
 *      ML_CGI_INVALID_COOKIE_NAME
 *      ML_CGI_INVALID_COOKIE_VALUE
 *      ML_CGI_INVALID_COOKIE_EXPIRATION
 *
 * ----> This version does not use the arguments path, domain and security.
 */
unsigned mlCgiSetCookie (char *, char *, unsigned long, char *, char *, char *);


/*---------------------------------------------------------------------------*/
/*
 *      Get the cookie value received from a client browser.
 *
 * Arguments:
 *      char * - cookie name (output).
 *      unsigned - cookie name maximum length (input)
 *      char * - cookie value (output)
 *      unsigned - cookie value maximum length (input)
 *
 * Returned Values:
 *      ML_CGI_OK or
 *      ML_CGI_INVALID_COOKIE_NAME
 *      ML_CGI_INVALID_COOKIE_VALUE
 *
 */
unsigned mlCgiGetCookie (char *, unsigned, char *, unsigned);

/*---------------------------------------------------------------------------*/
/*
 *      Get a specific cookie value received from a client browser.
 *
 * Arguments:
 *      char * - cookie name (input).
 *      unsigned - cookie name maximum length (input)
 *      char * - cookie value (output)
 *      unsigned - cookie value maximum length (input)
 *
 * Returned Values:
 *      ML_CGI_OK or
 *      ML_CGI_INVALID_COOKIE_NAME
 *      ML_CGI_INVALID_COOKIE_VALUE
 *      ML_CGI_COOKIE_NOT_FOUND
 *
 */
unsigned mlCgiGetSpecificCookie (char *, unsigned, char *, unsigned);

#endif
