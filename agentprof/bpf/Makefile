# Build the eBPF object. Needs only clang and the libbpf headers
# (apt install clang libbpf-dev); no kernel headers, no BTF.
ARCH_INC := /usr/include/$(shell gcc -dumpmachine 2>/dev/null || echo $(shell uname -m)-linux-gnu)

all: agentprof.bpf.o

agentprof.bpf.o: agentprof.bpf.c
	clang -O2 -g -target bpf -I$(ARCH_INC) -c $< -o $@

clean:
	rm -f agentprof.bpf.o
