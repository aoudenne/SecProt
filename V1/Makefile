#**MakefileFile***********************************************************************
#
#  FileName    [Makefile]
#
#  Author      [Igor Melatti]
#
#  Copyright   [
#  This file contains the Makefile of secur CMurphi example.
#  Copyright (C) 2009-2012 by Sapienza University of Rome. 
#
#  CMurphi is free software; you can redistribute it and/or 
#  modify it under the terms of the GNU Lesser General Public 
#  License as published by the Free Software Foundation; either 
#  of the License, or (at your option) any later version.
#
#  CMurphi is distributed in the hope that it will be useful, 
#  but WITHOUT ANY WARRANTY; without even the implied warranty of 
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public 
#  License along with this library; if not, write to the Free Software 
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA.
#
#  To contact the CMurphi development board, email to <melatti@di.uniroma1.it>. ]
#
#*************************************************************************************

INCLUDEPATH = ../../include
SRCPATH = ../../src/

CXX = g++

CFLAGS = 

# optimization
OFLAGS = -ggdb
#OFLAGS = -O2

#Murphi options
MURPHIOPTS = -b -c

all: protocolV1.model  protocolV1.cache  protocolV1.disk 
splitfile: protocolV1.cache.splitfile  protocolV1.disk.splitfile  

# rules for compiling
protocolV1.model: protocolV1.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV1.model protocolV1.cpp -I${INCLUDEPATH} -lm



protocolV1.cache: protocolV1.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV1.cache protocolV1.cache.cpp -I${INCLUDEPATH} -lm



protocolV1.cache.splitfile: protocolV1.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV1.cache.splitfile protocolV1.cache.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV1.disk.splitfile: protocolV1.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV1.disk.splitfile protocolV1.disk.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV1.disk: protocolV1.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV1.disk protocolV1.disk.cpp -I${INCLUDEPATH} -lm



protocolV1.cpp: protocolV1.m
	${SRCPATH}mu protocolV1.m


protocolV1.cache.cpp: protocolV1.m
	${SRCPATH}mu --cache -b -c protocolV1.m
	mv protocolV1.cpp protocolV1.cache.cpp



protocolV1.disk.cpp: protocolV1.m
	${SRCPATH}mu --disk protocolV1.m
	mv protocolV1.cpp protocolV1.disk.cpp



clean:
	rm -f *.cpp protocolV1.model  protocolV1.cache  protocolV1.disk  protocolV1.cache.splitfile  protocolV1.disk.splitfile  
