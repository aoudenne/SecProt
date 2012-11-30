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

all: protocolV2.model  protocolV2.cache  protocolV2.disk 
splitfile: protocolV2.cache.splitfile  protocolV2.disk.splitfile  

# rules for compiling
protocolV2.model: protocolV2.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV2.model protocolV2.cpp -I${INCLUDEPATH} -lm



protocolV2.cache: protocolV2.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV2.cache protocolV2.cache.cpp -I${INCLUDEPATH} -lm



protocolV2.cache.splitfile: protocolV2.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV2.cache.splitfile protocolV2.cache.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV2.disk.splitfile: protocolV2.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV2.disk.splitfile protocolV2.disk.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV2.disk: protocolV2.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV2.disk protocolV2.disk.cpp -I${INCLUDEPATH} -lm



protocolV2.cpp: protocolV2.m
	${SRCPATH}mu protocolV2.m


protocolV2.cache.cpp: protocolV2.m
	${SRCPATH}mu --cache -b -c protocolV2.m
	mv protocolV2.cpp protocolV2.cache.cpp



protocolV2.disk.cpp: protocolV2.m
	${SRCPATH}mu --disk protocolV2.m
	mv protocolV2.cpp protocolV2.disk.cpp



clean:
	rm -f *.cpp protocolV2.model  protocolV2.cache  protocolV2.disk  protocolV2.cache.splitfile  protocolV2.disk.splitfile  
