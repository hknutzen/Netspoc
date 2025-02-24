VPATH = ../

ignore=$(wildcard ../*ipv*.t) ../options.t ../nat.t
files=$(filter-out $(ignore), $(wildcard ../*.t))

all : $(patsubst ../%.t, %_ipv6.t, $(files))

%_ipv6.t: %.t
	perl convert.pl $^ .

.PHONY : clean

clean :
	rm *_ipv6.t
