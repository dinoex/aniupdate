
NO_WARN=	yes
#CC=	gcc33

CFLAGS+=	-g
LDFLAGS+=	-g

CFLAGS+=	-O

#CFLAGS+=	-std=iso9899:1999
CFLAGS+=	-W
CFLAGS+=	-Wall
CFLAGS+=	-Waggregate-return
CFLAGS+=	-Wbad-function-cast
CFLAGS+=	-Wcast-align
CFLAGS+=	-Wcast-qual
CFLAGS+=	-Wchar-subscripts
CFLAGS+=	-Wcomment
CFLAGS+=	-Wconversion
CFLAGS+=	-Werror-implicit-function-declaration
CFLAGS+=	-Wformat
#CFLAGS+=	-Wid-clash-30
CFLAGS+=	-Wimplicit
#CFLAGS+=	-Wimplicit-function-delcaration
CFLAGS+=	-Wimplicit-int
#CFLAGS+=	-Winline
#CFLAGS+=	-Wlong-long
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wmissing-prototypes
CFLAGS+=	-Wnested-externs
CFLAGS+=	-Wno-import
CFLAGS+=	-Wno-parentheses
#CFLAGS+=	-Woverloaded-virtual
CFLAGS+=	-Wparentheses
CFLAGS+=	-Wpointer-arith
CFLAGS+=	-Wredundant-decls
CFLAGS+=	-Wreturn-type
CFLAGS+=	-Wshadow
CFLAGS+=	-Wsign-compare
CFLAGS+=	-Wstrict-prototypes
CFLAGS+=	-Wswitch
#CFLAGS+=	-Wtraditional
CFLAGS+=	-Wtrigraphs
CFLAGS+=	-Wuninitialized
CFLAGS+=	-Wunused
CFLAGS+=	-Wwrite-strings
#CFLAGS+=	-pedantic

.if exists(Makefile.local)
.include "Makefile.local"
.endif

all:	aniupdate

PROG=	aniupdate
.if exists(aniupdate.c)
SRCS=	aniupdate.m
.else
SRCS=	aniupdate.m
.if !exists(/usr/lib/libcipher.so)
OBJCLIBS?=	-lobjc -lc_r
.endif
.endif

NOMAN=YES

.include <bsd.prog.mk>

# eof
