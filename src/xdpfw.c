#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <linux/types.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include <bpf.h>
#include <libbpf.h>

#include "xdpfw.h"
#include "config.h"
#include "cmdline.h"

#include <ctype.h>

/* XDP section 

#define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0)
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#define XDP_FLAGS_DRV_MODE		(1U << 2)
#define XDP_FLAGS_HW_MODE		(1U << 3)
#define XDP_FLAGS_REPLACE		(1U << 4)
#define XDP_FLAGS_MODES			(XDP_FLAGS_SKB_MODE | \
					 XDP_FLAGS_DRV_MODE | \
					 XDP_FLAGS_HW_MODE)
#define XDP_FLAGS_MASK			(XDP_FLAGS_UPDATE_IF_NOEXIST | \
					 XDP_FLAGS_MODES | XDP_FLAGS_REPLACE)*/


// Other variables.
static __u8 cont = 1;
static int filtersmap = -1,filtersmap6 = -1;
static int statsmap = -1;
static int portsmap = -1;


static int sock = -1;
#define SOCKET int
#define PKTBUF_SIZE 2048

/* Keep this in sync with /usr/src/linux/include/linux/route.h */
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */

char	g_cAttEth[32] = { 0 };
char	g_cRcvEth[32] = { 0 }; 


void signalHndl(int tmp)
{
    cont = 0;
}


static void print_data(char *name,unsigned char *data,int len)
{
    int i,j,k;

    
    if(name) printf("-------%s-------%dbytes-----------------------------\n",name,len);

    for (i=0; i<len; i+=16) {
        printf("| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            printf("%.2x ",data[j]);
        for (; k<16; ++k)
            printf("   ");
       printf("|");
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            unsigned char c = data[j];
            if (!isprint(c) || (c=='\t')) c = '.';
            printf("%c",c);
        }
        for (; k<16; ++k)
            printf("   ");
        printf("|\n");
    }

}


/* *****************open udp socket for rcv log********************* */

SOCKET open_socket(int local_port, int bind_any) {
  SOCKET              sock_fd;
  struct sockaddr_in  local_address;
  int                 sockopt = 1;

  if((sock_fd = socket(PF_INET, SOCK_DGRAM, 0))  < 0) {
    printf("Unable to create socket [%s][%d]\n",strerror(errno), sock_fd);
    return(-1);
  }

#ifndef WIN32
  /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

  //setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,(char *)&sockopt, sizeof(sockopt));

  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons(local_port);
  local_address.sin_addr.s_addr = htonl(bind_any ? INADDR_ANY : INADDR_LOOPBACK);

  if(bind(sock_fd,(struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
    printf("Bind error on local port %u [%s]\n", local_port, strerror(errno));
    return(-1);
  }

  return(sock_fd);
}


static void init_hi_ports_map(void) {
    unsigned int  i,v;

    v = 0;
    for (i = 0; i < MAX_FILTER_PORTS;i++) {
          // Attempt to update BPF map.
        if (bpf_map_update_elem(portsmap, &i, &v, BPF_ANY) == -1)        {
            fprintf(stderr, "Error updating BPF item #%d\n", i);
        }
    }
   

}

static void process_udp(char *data,int datalen,const struct sockaddr_in * sender_sock)
{
 
     unsigned int addr = 0,curaddr = 0,nextaddr = 0;
     int          num = 0,fd = 0,len = 16;
     __uint128_t  dstip6 = 0,curip6 = 0,nextip6 = 0;
    
    if (datalen < 32)
        return;

     //print_data("process_udp:", (unsigned char *)data,32);
    if (memcmp(data,"INIT_PORTS_MAP",12) == 0) { 
        init_hi_ports_map();
    }

    
    if (memcmp(data,"CLEAR_BADIP",11) == 0) {    
        printf("CLEAR_BADIP\n");
         
        fd = bpf_map_get_next_key(filtersmap,NULL,&nextaddr);
        if (fd != 0)
            return;
        
        while(fd == 0) {
            curaddr = nextaddr;
            if (curaddr == 0)
                break;
      
            bpf_map_delete_elem(filtersmap, &curaddr);            
            fd = bpf_map_get_next_key(filtersmap,&curaddr,&nextaddr);
        }


        
        fd = bpf_map_get_next_key(filtersmap6,NULL,&nextip6);
        if (fd != 0)
               return;
           
        while(fd == 0) {
               curip6 = nextip6;
               if (curip6 == 0)
                   break;
             
               bpf_map_delete_elem(filtersmap6, &curip6);            
               fd = bpf_map_get_next_key(filtersmap6,&curip6,&nextip6);
        }     


        
       
        return; 
    }

    if (memcmp(data,"INSERT_BADIP",11) == 0) {   
        while (len < datalen) {
            memcpy(&addr,data + len, 4);          
            if (addr == 0)
                break; 

     
              // Attempt to update BPF map.
            if (bpf_map_update_elem(filtersmap, &addr, &addr, BPF_ANY) == -1)
            {
                fprintf(stderr, "Error updating BPF item #%x\n", addr);
            }
        
            num++;
            len += 4;
        }
 
        return; 
    }

    if (memcmp(data,"ADD_BAD_IPV6",11) == 0) {   
        while (len < datalen) {
            memcpy(&dstip6,data + len, 16); 
            
            if (dstip6 == 0)
                break; 

           
              // Attempt to update BPF map.
            addr = 128;
            if (bpf_map_update_elem(filtersmap6, &dstip6, &addr, BPF_ANY) == -1)
            {
                fprintf(stderr, "Error updating BPF item #%x\n", (unsigned int)dstip6);
            }
        
            num++;
            len += 16;
        }
 
        return; 
    }

}

static int  run_loop(void)
{
    int               keep_running = 1;
    int               rc;
    int               bread;
    int               max_sock;
    fd_set            socket_mask;
    struct timeval    wait_time;
    time_t            now = 0,last = 0,last_ip = 0;
    char              pktbuf[PKTBUF_SIZE];

    __u32 key = 0;
    struct stats stats[MAX_CPUS];
    __u64 allowed = 0;
    __u64 dropped = 0;
    // Receive CPU count for stats map parsing.
    int cpus = get_nprocs_conf(); 
    memset(stats, 0, sizeof(struct stats) * MAX_CPUS);
    printf("cpu=%d MAX_CPUS=%d\n",cpus,MAX_CPUS);
    
    while(keep_running && cont) 
    {            
       if((now - last) > 1)
       {
            last = now; 
            allowed   = dropped = 0;
            if (bpf_map_lookup_elem(statsmap, &key, stats) != 0)
            {
                fprintf(stderr, "Error performing stats map lookup. Stats map FD => %d.\n", statsmap);
                continue;
            }

            for (int i = 0; i < cpus; i++)
            {
                // Although this should NEVER happen, I'm seeing very strange behavior in the following GitHub issue.
                // https://github.com/gamemann/XDP-Firewall/issues/10
                // Therefore, before accessing stats[i], make sure the pointer to the specific CPU ID is not NULL.
                if (&stats[i] == NULL)
                {
                    fprintf(stderr, "Stats array at CPU ID #%d is NULL! Skipping...\n", i);

                    continue;
                }

                allowed += stats[i].allowed;
                dropped += stats[i].dropped;
            }

            fflush(stdout);
            fprintf(stdout, "\rPackets Allowed: %llu | Packets Dropped: %llu", allowed, dropped);
   
       
            last = now;      
                      
       }
    
       FD_ZERO(&socket_mask);           
       FD_SET(sock, &socket_mask);

      

    
       wait_time.tv_sec = 1; wait_time.tv_usec = 0;
       rc = select(sock+1, &socket_mask, NULL, NULL, &wait_time);
    
       now = time(NULL);
    
       if(rc > 0) 
       {
            if(FD_ISSET(sock, &socket_mask)) 
            {
               struct sockaddr_in  sender_sock;
               socklen_t           i;

              // memset(pktbuf,0,sizeof(PKTBUF_SIZE));
               i = sizeof(sender_sock);
               bread = recvfrom(sock, pktbuf, PKTBUF_SIZE-1, 0/*flags*/,
                        (struct sockaddr *)&sender_sock, (socklen_t*)&i);
            
               if(bread < 0) 
               {
                 /* For UDP bread of zero just means no data (unlike TCP). */
                 /* The fd is no good now. Maybe we lost our interface. */
                 printf("recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                 keep_running = 0;
                 break;
               }
            
               /* We have a datagram to process */
               if(bread > 0) 
               {
                 /* And the datagram has data (not just a header) */
                 pktbuf[bread] = '\0';
                 process_udp(pktbuf, bread,&sender_sock);
               } 
               
         
               } 
       }
       //else 
       //{
        // printf("\nmain timeout\n");
       //}
      
    
    } /* while */
    return 0;
}

/**
 * Finds a BPF map's FD.
 * 
 * @param bpf_obj A pointer to the BPF object.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
*/
int findmapfd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}


/**
 * Loads a BPF object file.
 * 
 * @param filename The path to the BPF object file.
 * 
 * @return BPF's program FD.
*/
int loadbpfobj(const char *filename, __u8 offload, int ifidx)
{
    int fd = -1;

    // Create attributes and assign XDP type + file name.
    struct bpf_prog_load_attr attrs = 
    {
		.prog_type = BPF_PROG_TYPE_XDP,
	};

    // If we want to offload the XDP program, we must send the ifindex item to the interface's index.
    if (offload)
    {
        attrs.ifindex = ifidx;
    }
    
    attrs.file = filename;

    // Check if we can access the BPF object file.
    if (access(filename, O_RDONLY) < 0) 
    {
        fprintf(stderr, "Could not read/access BPF object file :: %s (%s).\n", filename, strerror(errno));

        return fd;
    }

    struct bpf_object *obj = NULL;
    int err;

    // Load the BPF object file itself.
    err = bpf_prog_load_xattr(&attrs, &obj, &fd);

    if (err) 
    {
        fprintf(stderr, "Could not load XDP BPF program :: %s.\n", strerror(errno));

        return fd;
    }

    struct bpf_program *prog;

    // Load the BPF program itself by section name and try to retrieve FD.
    prog = bpf_object__find_program_by_title(obj, "hi_xdp_prog");
    fd = bpf_program__fd(prog);

    if (fd < 0) 
    {
        printf("XDP program not found by section/title :: xdp_prog (%s).\n", strerror(fd));

        return fd;
    }

    // Retrieve BPF maps.
    filtersmap =  findmapfd(obj, "hi_ip_blacklist_map");
    filtersmap6 = findmapfd(obj, "hi_ip6_blacklist_map");
    statsmap = findmapfd(obj, "hi_stats_map");
    portsmap = findmapfd(obj, "hi_ports_map");

    return fd;
}


/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    __u32 mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}


/* Caller must free return string. */

char *proc_gen_fmt(char *name, int more, FILE * fh,...)
{
    char buf[512], format[512] = "";
    char *title, *head, *hdr;
    va_list ap;

    if (!fgets(buf, (sizeof buf) - 1, fh))
	return NULL;
    strcat(buf, " ");

    va_start(ap, fh);
    title = va_arg(ap, char *);
    for (hdr = buf; hdr;) {
	while (isspace(*hdr) || *hdr == '|')
	    hdr++;
	head = hdr;
	hdr = strpbrk(hdr, "| \t\n");
	if (hdr)
	    *hdr++ = 0;

	if (!strcmp(title, head)) {
	    strcat(format, va_arg(ap, char *));
	    title = va_arg(ap, char *);
	    if (!title || !head)
		break;
	} else {
	    strcat(format, "%*s");	/* XXX */
	}
	strcat(format, " ");
    }
    va_end(ap);

    if (!more && title) {
	fprintf(stderr, "warning: %s does not contain required field %s\n",
		name, title);
	return NULL;
    }
    return strdup(format);
}


void get_best_iface(void) {

    char buff[1024], iface[17], flags[64];
    char gate_addr[128], net_addr[128];
    char mask_addr[128];
    int num, iflags, metric, refcnt, use, mss, window, irtt;
    FILE *fp = fopen("/proc/net/route", "r");
    char *fmt;

    
	
	snprintf(g_cAttEth, sizeof(g_cAttEth), "%s", "eth0");
	snprintf(g_cRcvEth, sizeof(g_cRcvEth), "%s", "eth0");

    if (fp == NULL)
        return;

    
    irtt = 0;
    window = 0;
    mss = 0;

     fmt = proc_gen_fmt("/proc/net/route", 0, fp,
		       "Iface", "%16s",
		       "Destination", "%127s",
		       "Gateway", "%127s",
		       "Flags", "%X",
		       "RefCnt", "%d",
		       "Use", "%d",
		       "Metric", "%d",
		       "Mask", "%127s",
		       "MTU", "%d",
		       "Window", "%d",
		       "IRTT", "%d",
		       NULL);
    /* "%16s %127s %127s %X %d %d %d %127s %d %d %d\n" */

    if (!fmt)
	   return; 

    while (fgets(buff, 1023, fp)) {
        num = sscanf(buff, fmt,
		     iface, net_addr, gate_addr,
		     &iflags, &refcnt, &use, &metric, mask_addr,
		     &mss, &window, &irtt);
	    if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY))
	        continue;

        //printf("%s\n",buff);
        printf("Iface=%s       Destination=%s      gate_addr=%s       iflags=%x\n",iface,net_addr,gate_addr,iflags);        
        snprintf(g_cAttEth, sizeof(g_cAttEth), "%s", iface);
        snprintf(g_cRcvEth, sizeof(g_cRcvEth), "%s", iface);
        break;

   }


    free(fmt);
    (void) fclose(fp);


}

int main(int argc, char * const argv[]) 
{
    // Parse the command line.
      struct cmdline cmd = 
      {
          .cfgfile = "/etc/xdpfw/xdpfw.conf",
          .help = 0,
          .list = 0,
          .offload = 0
      };


    sock = open_socket(16888, 0 /*bind ANY*/);
    if (-1 == sock) 
    {
        printf("Failed to open main socket. %s", strerror(errno));
        return 0;
    }
    
    
    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    get_best_iface();

    
    // Get device.
    int ifidx;
    
    if ((ifidx = if_nametoindex(g_cRcvEth)) < 0)
    {
         fprintf(stderr, "Error finding device %s.\n", g_cRcvEth);    
         return EXIT_FAILURE;
    }

     if (argc == 2 && memcmp(argv[1],"stop",4) == 0) {
        // Detach XDP program.
        attachxdp(ifidx, -1, &cmd);
        printf("stop XDP %s\n",g_cRcvEth);
        return EXIT_FAILURE;
    }

     // Detach XDP program.
     attachxdp(ifidx, -1, &cmd); 
    
    // XDP variables.
    int progfd;
    const char *filename = "/hiproc/lib/hi_xdpfw_kern.o";

    // Get XDP's ID.
    progfd = loadbpfobj(filename, cmd.offload, ifidx);

    if (progfd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }

   
    
    // Attach XDP program.
    int res = attachxdp(ifidx, progfd, &cmd);

    if (res != XDP_FLAGS_HW_MODE && res != XDP_FLAGS_DRV_MODE && res != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(res), res);

        return EXIT_FAILURE;
    }

    // Check for valid maps.
    if (filtersmap < 0)    {
        fprintf(stderr, "Error finding 'hi_ip_blacklist_map' BPF map.\n");
        return EXIT_FAILURE;
    }

    if (filtersmap6 < 0)    {
        fprintf(stderr, "Error finding 'hi_ip6_blacklist_map' BPF map.\n");
        return EXIT_FAILURE;
    }

    if (statsmap < 0)    {
        fprintf(stderr, "Error finding 'hi_stats_map' BPF map.\n");
        return EXIT_FAILURE;
    }

    
    if (portsmap < 0)    {
        fprintf(stderr, "Error finding 'hi_ports_map' BPF map.\n");
        return EXIT_FAILURE;
    }
    
    signal(SIGINT, signalHndl);
    
    init_hi_ports_map();   
    run_loop();
    
    close(sock);
    
    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);
    
    printf("\nexit ok\n");
}

