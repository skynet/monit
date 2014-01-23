AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = ../libmonit.la
AM_CPPFLAGS = -I../src/ -I../src/util -I../src/net -I../src/io -I../src/exceptions -I../src/thread 

noinst_PROGRAMS = StrTest \
                  SystemTest \
                  ListTest \
                  DirTest \
                  StringBufferTest \
                  InputStreamTest \
                  OutputStreamTest \
                  FileTest \
                  ExceptionTest \
                  NetTest \
                  TimeTest \
                  CommandTest

StrTest_SOURCES = StrTest.c
CommandTest_SOURCES = CommandTest.c
SystemTest_SOURCES = SystemTest.c
ListTest_SOURCES = ListTest.c
DirTest_SOURCES = DirTest.c
StringBufferTest_SOURCES = StringBufferTest.c
InputStreamTest_SOURCES = InputStreamTest.c
OutputStreamTest_SOURCES = OutputStreamTest.c
FileTest_SOURCES = FileTest.c
ExceptionTest_SOURCES = ExceptionTest.c
NetTest_SOURCES = NetTest.c
TimeTest_SOURCES = TimeTest.c

DISTCLEANFILES = *~ 

distclean-local: 
	-rm -f Makefile.in

verify:
	@/bin/bash ./test.sh

