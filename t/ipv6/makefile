VPATH = ../

all : $(patsubst ../%.t, %_ipv6.t, $(wildcard ../*.t))

%_ipv6.t: %.t
	perl convert.pl $^ .

.PHONY : clean

clean :
	rm *_ipv6.t
