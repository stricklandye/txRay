package tracer

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type tcp_key_t bpf ../bpf/bpf.c

type TxRayTracer struct {
	recvHookPoint link.Link
	sendHookPoint link.Link
	objs          bpfObjects
	conf          *Config
	packets       map[bpfTcpKeyT]bpfTcpValT
}

type Config struct {
	Addr      string
	Interface string
	Port      string
}

var protocolMap = make(map[uint8]string)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	protocolMap[1] = "ICMP"
	protocolMap[2] = "IGMP"
	protocolMap[4] = "IPIP"
	protocolMap[6] = "TCP"
	protocolMap[17] = "UDP"
}
func NewTracer(conf *Config) *TxRayTracer {
	return &TxRayTracer{conf: conf, packets: make(map[bpfTcpKeyT]bpfTcpValT)}
}

func (t *TxRayTracer) Start() {
	t.attach()
	go func() {
		ticker := time.NewTicker(time.Millisecond * 100)
		for {
			select {
			case <-ticker.C:
				t.collect()
			}
		}
	}()
}

func (t *TxRayTracer) collect() {
	var key bpfTcpKeyT
	var val bpfTcpValT
	iter := t.objs.TrafficMap.Iterate()
	for iter.Next(&key, &val) {
		var visited []bpfTcpKeyT
		visited = append(visited, key)
		devName := Clean(string(val.DevName[:]))
		if devName == t.conf.Interface {
			exists, ok := t.packets[key]
			if !ok {
				t.packets[key] = val
			} else {
				exists.Sent += val.Sent
				exists.Recv += val.Recv
				t.packets[key] = exists
			}
		}
		_, err := t.objs.TrafficMap.BatchDelete(visited, nil)
		if err != nil {
			log.Errorf("delete BPF data error:%v", err)
		}
	}
}

func (t *TxRayTracer) attach() {
	if !BtfAvailable() {
		log.Fatalf("BTF is required")
		return
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		// print bpf verifier error
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
		}
		log.Fatalf("loading objects: %v", err)
	}
	tpSend, err := link.Tracepoint("net", "net_dev_queue", objs.TpNetDevQueue, nil)
	if err != nil {
		log.Fatalf("opening tracepoint at net_dev_queue error:%v", err)
	}
	tpRecv, err := link.Tracepoint("net", "netif_receive_skb", objs.TpNetifReceiveSkb, nil)
	if err != nil {
		log.Fatalf("opening tracepoint at netif_receive_skb error:%v", err)
	}
	t.objs = objs
	t.recvHookPoint = tpRecv
	t.sendHookPoint = tpSend
}

func (t *TxRayTracer) Stop() {
	log.Infof("stop txRay")
	t.sendHookPoint.Close()
	t.recvHookPoint.Close()
	t.objs.Close()
	t.analyze()
}

func (t *TxRayTracer) analyze() {
	fmt.Printf("%-12s %-20s %-24s %-24s %-12s %-12s %-12s %s\n",
		"pid", "comm", "saddr", "daddr", "protocol", "sent_bytes", "recv_bytes", "interface")
	for key, val := range t.packets {
		if val.Pid == 0 {
			continue
		}
		lport := strconv.Itoa(int(key.Lport))
		dport := strconv.Itoa(int(key.Dport))
		if t.conf.Port != "" && !(lport == t.conf.Port || dport == t.conf.Port) {
			continue
		}
		srcIp := Int2IP(key.Saddr).String()
		dstIp := Int2IP(key.Daddr).String()
		if t.conf.Addr != "" && !(srcIp == t.conf.Addr || dstIp == t.conf.Addr) {
			continue
		}
		saddr := srcIp + ":" + lport
		daddr := dstIp + ":" + dport
		name, _ := protocolMap[key.Protocol]
		fmt.Printf("%-12d %-20s %-24s %-24s %-12s %-12d %-12d %s\n",
			val.Pid, Clean(string(val.Comm[:])), saddr, daddr, name, val.Sent, val.Recv, Clean(string(val.DevName[:])))
	}
}
