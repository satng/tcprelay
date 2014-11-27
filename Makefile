# Makefile for tcprelay
#
# Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

CC = gcc
CXX = g++
LD = gcc

CFLAGS = -pipe -W -Wall -Wno-unused-parameter -std=gnu99
CFLAGS += -O2 -fno-strict-aliasing
LDFLAGS = -Wl,-O1
LIBS = -lev

.phony: all clean

all: tcprelay

clean:
	rm -f tcprelay *.o 

distclean: clean

tcprelay: tcprelay.o log.o
	$(LD)  $(LDFLAGS)  -o $@  $^ $(LIBS)

tcprelay.o: tcprelay.c log.h
	$(CC)  $(CFLAGS)  -c  -o $@  $<

log.o: log.c log.h
	$(CC)  $(CFLAGS)  -c  -o $@  $<
