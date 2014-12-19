# Copyright (C) Tildeslash Ltd. All rights reserved.

AUTOMAKE_OPTIONS = foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS  = -I m4

SUBDIRS         = . test

EXTRA_DIST      = README COPYING bootstrap test src config

AM_CPPFLAGS     = $(CPPFLAGS) $(DBCPPFLAGS) -I./src -I./src/exceptions -I./src/io -I./src/net -I./src/util -I./src/thread

# libmonit is built static
noinst_LTLIBRARIES = libmonit.la

libmonit_la_SOURCES = \
		  src/Bootstrap.c \
                  src/exceptions/assert.c \
                  src/exceptions/Exception.c \
                  src/io/Dir.c \
                  src/io/File.c \
                  src/io/InputStream.c \
                  src/io/OutputStream.c \
                  src/system/Mem.c \
                  src/system/Net.c \
                  src/system/Time.c \
                  src/system/Command.c \
                  src/system/System.c \
                  src/system/NetStatistics.c \
                  src/util/List.c \
                  src/util/Str.c \
                  src/util/StringBuffer.c \
                  src/thread/Thread.c

dist-hook::
	-rm -rf `find $(distdir) -name "._*"`
	-rm -rf `find $(distdir) -name ".DS_Store"`
	-rm -rf `find $(distdir) -name ".libs"`
	-rm -rf `find $(distdir) -name ".git"`
	-rm -f $(distdir)/src/xconfig.h $(distdir)/Makefile $(distdir)/src/stamp-* 

clean-local:
	-rm -f `find . -name "*.o" -o -name "*.lo" -o -name "*.loT" -o -name "*~"`

distclean-local: 
	-rm -rf autom4te.cache/ 

cleanall: clean distclean
	-rm -f Makefile.in test/Makefile.in src/Makefile.in configure aclocal.m4 src/xconfig.h.in
	-rm -rf m4 config

verify: libmonit.la
	cd $(srcdir)/test && $(MAKE) verify	
