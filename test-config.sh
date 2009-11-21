CFLAGS=-DDEBUG
LDFLAGS=-lefence

export CFLAGS LDFLAGS

./configure $*
