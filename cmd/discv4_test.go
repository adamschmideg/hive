package main

import (
	"crypto/ecdsa"
	"flag"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/hive/simulators/common"
	"net"
	"testing"
)

var enodeID string

func init() {
	flag.StringVar(&enodeID, "enode", "", "enode:... as per `admin.nodeInfo.enode`")
}

//ripped out from the urlv4 code
func signV4Compat(r *enr.Record, pubkey *ecdsa.PublicKey) {
	r.Set((*enode.Secp256k1)(pubkey))
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil {
		panic(err)
	}
}

func getMacAddr() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var as []string
	for _, ifa := range interfaces {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}

func MakeNode(pubkey *ecdsa.PublicKey, ip net.IP, tcp, udp int, mac *string) *enode.Node {
	var r enr.Record
	if ip != nil {
		r.Set(enr.IP(ip))
	}
	if udp != 0 {
		r.Set(enr.UDP(udp))
	}
	if tcp != 0 {
		r.Set(enr.TCP(tcp))
	}
	if mac != nil {
		r.Set(common.MacENREntry(*mac))
	}

	signV4Compat(&r, pubkey)
	n, err := enode.New(v4CompatID{}, &r)
	if err != nil {
		panic(err)
	}
	return n
}

type v4CompatID struct {
	enode.V4ID
}

func (v4CompatID) Verify(r *enr.Record, sig []byte) error {
	var pubkey enode.Secp256k1
	return r.Load(&pubkey)
}

func TestDiscV4(t *testing.T) {
	targetNode, err := enode.ParseV4(enodeID)
	if err != nil {
		t.Error(err, enodeID)
	}
	ipAddr := targetNode.IP()
	macAddresses, err := getMacAddr()
	if err != nil {
		t.Error("No mac address")
	}
	macAddr := macAddresses[7]

	targetNode = MakeNode(targetNode.Pubkey(), ipAddr, targetNode.TCP(), 30303, &macAddr)

	//v4udp := setupv4UDP(t)
	//v4udp.Ping()
}
