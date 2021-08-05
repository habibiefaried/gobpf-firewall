package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct allowtablestr {
    u32 Source;
    u32 Dest;
};

typedef struct {
	u32 Source;
	u32 Dest;
	char Verdict[256];
} chown_event_t;

BPF_PERF_OUTPUT(chown_events);
BPF_TABLE("array", int, long, dropcnt, 256);
BPF_HASH(allowtable, struct allowtablestr, u32, 256);

static inline void copyStr(char a[], char b[]){
	int c = 0;
	while (b[c] != '\0') {
		a[c] = b[c];
		c++;
	}
	a[c] = '\0';
}

static inline int parse_ipv4(struct xdp_md *ctx, void *data, u64 nh_off, void *data_end) {
	
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
        return 0;

    struct allowtablestr at = {};
    chown_event_t event = {};
    
    event.Source = iph->saddr;
	event.Dest = iph->daddr;

	at.Source = iph->saddr;
	at.Dest = iph->daddr;

	u32 *result = allowtable.lookup(&at);
    if (result) {
    	copyStr(event.Verdict,"PASS");
		chown_events.perf_submit(ctx, &event, sizeof(event));
    } else {
    	copyStr(event.Verdict,"DENIED");
		chown_events.perf_submit(ctx, &event, sizeof(event));
    }

    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

int xdp_prog1(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    int index;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    // While the following code appears to be duplicated accidentally,
    // it's intentional to handle double tags in ethernet frames.
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
            h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP))
       index = parse_ipv4(ctx, data, nh_off, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
       index = parse_ipv6(data, nh_off, data_end);
    else
       index = 0;

    value = dropcnt.lookup(&index);
    if (value) lock_xadd(value, 1);

    return XDP_PASS;
}
`

type chownEvent struct {
	Source  uint32
	Dest    uint32
	Verdict [256]byte
}

type allowTable struct {
   Source  uint32
   Dest    uint32
}

var nativeEndian binary.ByteOrder

func main() {
	var device string
	setEndianness()
	
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
		fmt.Printf("e.g.: %v eth0\n", os.Args[0])
		os.Exit(1)
	}
	device = os.Args[1]

	module := bpf.NewModule(source, []string{
		"-w",
	})
	defer module.Close()

	fn, err := module.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Println("Dropping packets, hit CTRL+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	/* Initialize bpf map table */
	dropcnt := bpf.NewTable(module.TableId("dropcnt"), module)

	table := bpf.NewTable(module.TableId("chown_events"), module)
	channel := make(chan []byte)
	lostChannel := make(chan uint64)
	perfMap, err := bpf.InitPerfMap(table, channel, lostChannel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}
	allowtable := bpf.NewTable(module.TableId("allowtable"), module)
	/* */

	vals := make([]byte, 4)
    nativeEndian.PutUint32(vals, 25)
    buf := new(bytes.Buffer)
    _ = binary.Write(buf, nativeEndian, allowTable{Source: 20490432, Dest: 1832429760})
    allowtable.Set(buf.Bytes(), vals)

	go func() {
		var event chownEvent
		for {
			data := <-channel //retrieve from polling data
			err := binary.Read(bytes.NewBuffer(data), nativeEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			verdict := (*C.char)(unsafe.Pointer(&event.Verdict))
			fmt.Printf("%d %d %s\n", event.Source, event.Dest, C.GoString(verdict))
		}
	}()

	perfMap.Start() //polling the event, to feed the bidirectional channel

	<-sig

	fmt.Printf("\n{IP protocol-number}: {total dropped pkts}\n")
	for it := dropcnt.Iter(); it.Next(); {
		key := bpf.GetHostByteOrder().Uint32(it.Key())
		value := bpf.GetHostByteOrder().Uint64(it.Leaf())

		if value > 0 {
			fmt.Printf("%v: %v pkts\n", key, value)
		}
	}
}
