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

INCLUDEPATH = ../../../include
SRCPATH = ../../../src/

CXX = g++

CFLAGS = 

# optimization
OFLAGS = -ggdb
#OFLAGS = -O2

#Murphi options
MURPHIOPTS = -b -c

all: protocolV0  protocolV0.cache  protocolV0.disk 
splitfile: protocolV0.cache.splitfile  protocolV0.disk.splitfile  

# rules for compiling
protocolV0: protocolV0.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV0 protocolV0.cpp -I${INCLUDEPATH} -lm



protocolV0.cache: protocolV0.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV0.cache protocolV0.cache.cpp -I${INCLUDEPATH} -lm



protocolV0.cache.splitfile: protocolV0.cache.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV0.cache.splitfile protocolV0.cache.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV0.disk.splitfile: protocolV0.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV0.disk.splitfile protocolV0.disk.cpp -I${INCLUDEPATH} -lm -DSPLITFILE



protocolV0.disk: protocolV0.disk.cpp
	${CXX} ${CFLAGS} ${OFLAGS} -o protocolV0.disk protocolV0.disk.cpp -I${INCLUDEPATH} -lm



protocolV0.cpp: protocolV0.m
	${SRCPATH}mu protocolV0.m


protocolV0.cache.cpp: protocolV0.m
	${SRCPATH}mu --cache -b -c protocolV0.m
	mv protocolV0.cpp protocolV0.cache.cpp



protocolV0.disk.cpp: protocolV0.m
	${SRCPATH}mu --disk protocolV0.m
	mv protocolV0.cpp protocolV0.disk.cpp



clean:
	rm -f *.cpp protocolV0  protocolV0.cache  protocolV0.disk  protocolV0.cache.splitfile  protocolV0.disk.splitfile  
