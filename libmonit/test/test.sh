#!/bin/bash

export PATH=$PATH:.

StrTest && \
TimeTest && \
SystemTest && \
ListTest && \
StringBufferTest && \
DirTest && \
InputStreamTest && \
OutputStreamTest && \
FileTest && \
ExceptionTest && \
NetTest && \
CommandTest
