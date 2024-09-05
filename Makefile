CC = clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o  $(LIBBPFSRC)/staticobjs/xsk.o

CONFIGSRC = config.c
CONFIGOBJ = config.o
CMDLINESRC = cmdline.c
CMDLINEOBJ = cmdline.o

XDPFWSRC = xdpfw.c
XDPFWOUT = xdpfw

XDPPROGSRC = xdpfw_kern.c
XDPPROGBC = xdpfw_kern.bc
XDPPROGOBJ = hi_xdpfw_kern.o

OBJS = $(BUILDDIR)/$(CONFIGOBJ) $(BUILDDIR)/$(CMDLINEOBJ)

LDFLAGS += -lelf -lz
INCS = -I $(LIBBPFSRC)

all: xdpfw xdpfw_filter utils
xdpfw: utils libbpf $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) $(LDFLAGS) $(INCS) -o $(BUILDDIR)/$(XDPFWOUT) $(LIBBPFOBJS) $(OBJS) $(SRCDIR)/$(XDPFWSRC)
xdpfw_filter:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -O2 -emit-llvm -c -o $(BUILDDIR)/$(XDPPROGBC) $(SRCDIR)/$(XDPPROGSRC)
	llc -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGBC)
utils:
	mkdir -p $(BUILDDIR)/
	chmod +x libbpf/scripts/*
	$(CC) -O2 -c -o $(BUILDDIR)/$(CONFIGOBJ) $(SRCDIR)/$(CONFIGSRC)
	$(CC) -O2 -c -o $(BUILDDIR)/$(CMDLINEOBJ) $(SRCDIR)/$(CMDLINESRC)
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/*.bc
	rm -f $(BUILDDIR)/$(XDPFWOUT)
install:
	mkdir -p /hiproc/lib/
	cp -n $(BUILDDIR)/hi_xdpfw_kern.o /hiproc/lib/
	cp -n $(BUILDDIR)/xdpfw /hiproc/lib/
	cp $(BUILDDIR)/$(XDPPROGOBJ) /hiproc/lib/$(XDPPROGOBJ)
	cp $(BUILDDIR)/$(XDPFWOUT) /usr/bin/$(XDPFWOUT)
.PHONY: libbpf all
.DEFAULT: all