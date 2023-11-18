network_monitor: network_monitor.c network_monitor.h network_monitor.skel.h
	gcc -g -Wall -O2 -o network_monitor network_monitor.c -lbpf

network_monitor.skel.h: network_monitor.bpf.o
	bpftool gen skeleton ./network_monitor.bpf.o > network_monitor.skel.h

network_monitor.bpf.o: network_monitor.bpf.c network_monitor.h
	clang -g -O2 -target bpf -c network_monitor.bpf.c		\
	      -o network_monitor.bpf.o

clean:
	rm -f network_monitor network_monitor.skel.h network_monitor.bpf.o