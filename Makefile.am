AUTOMAKE_OPTIONS = gnu
LDADD = libmlcgi.a
CFLAFS = @CFLAGS@ -Wall -c -D__ML_CGI_GLOBAL_VARIABLES__

bin_PROGRAMS = mailmonitor login.cgi logout.cgi editBlackList.cgi showEditBlackListForm.cgi showMenu.cgi showWelcomePage.cgi

mailmonitor_SOURCES					= mailmonitor.c functions.c
login_cgi_SOURCES					= login.c functions.c 
logout_cgi_SOURCES					= logout.c functions.c 
editBlackList_cgi_SOURCES 			= cgiEditBlackList.c functions.c 
showEditBlackListForm_cgi_SOURCES 	= showEditBlackListForm.c functions.c 
showMenu_cgi_SOURCES 				= showMenu.c functions.c 
showWelcomePage_cgi_SOURCES 		= showWelcomePage.c functions.c 

doxygen:
	doxygen doxygen.cfg
	chmod 755 $(HTML_DOC_DIR)

noinst_HEADERS = const.h functions.h

# man page
# man_MANS = mailmonitor.1x

# we want these in the dist tarball
EXTRA_DIST = doc/*
# EXTRA_DIST = mailmonitor.1x

copycgi:
	./copy
.PHONY: copycgi

all-local: copycgi

