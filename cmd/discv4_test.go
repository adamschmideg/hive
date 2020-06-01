package main

import (
	"crypto/ecdsa"
	"flag"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/hive/simulators/common"
	"github.com/ethereum/hive/simulators/devp2p"
	"net"
	"testing"
)

var (
	enodeID    string
	listenPort string
	natdesc    string
)

const (
	PingPacket     = 1
	GarbagePacket8 = 8
)

func init() {
	flag.StringVar(&enodeID, "enode", "", "enode:... as per `admin.nodeInfo.enode`")
	flag.StringVar(&listenPort, "listenPort", ":30304", "")
	flag.StringVar(&natdesc, "nat", "any", "port mapping mechanism (any|none|upnp|pmp|extip:<IP>)")
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

func setupv4UDP(l common.Logger) (devp2p.V4Udp, *net.UDPAddr) {
	var nodeKey *ecdsa.PrivateKey
	var restrictList *netutil.Netlist

	//Resolve an address (eg: ":port") to a UDP endpoint.
	addr, err := net.ResolveUDPAddr("udp", listenPort)
	if err != nil {
		panic(err)
	}

	//Create a UDP connection

	//wrap this 'listener' into a conn
	//but
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Fatalf("-ListenUDP: %v", err)
	}

	//The following just gets the local address, does something with NAT and converts into a
	//general address type.
	natm, err := nat.Parse(natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, nil, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}

		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}

	nodeKey, err = crypto.GenerateKey()

	if err != nil {
		utils.Fatalf("could not generate key: %v", err)
	}

	cfg := devp2p.Config{
		PrivateKey:   nodeKey,
		AnnounceAddr: realaddr,
		NetRestrict:  restrictList,
	}

	var v4UDP *devp2p.V4Udp

	if v4UDP, err = devp2p.ListenUDP(conn, cfg, l); err != nil {
		panic(err)
	}

	return *v4UDP, realaddr
}

func TestDiscV4(t *testing.T) {
	// Set up target node
	targetNode, err := enode.ParseV4(enodeID)
	if err != nil {
		t.Error(err, enodeID)
	}
	ipAddr := targetNode.IP()
	if ipAddr == nil {
		ipAddr = net.ParseIP("127.0.0.1")
	}
	udpPort := targetNode.UDP()
	if udpPort == 0 {
		udpPort = 30303
	}
	macAddresses, err := getMacAddr()
	if err != nil {
		t.Error("No mac address")
	}
	macAddr := macAddresses[7]
	targetNode = MakeNode(targetNode.Pubkey(), ipAddr, targetNode.TCP(), udpPort, &macAddr)
	t.Log("targetNode", targetNode)

	// Prep for calling ping
	v4udp, ourAddr := setupv4UDP(t)
	targetAddr := &net.UDPAddr{
		IP:   ipAddr,
		Port: udpPort,
	}

	badAddr := &net.UDPAddr{IP: []byte{0, 1, 2, 3}, Port: 1}
	type test struct {
		name            string
		description     string
		fromAddr        *net.UDPAddr
		toAddr          *net.UDPAddr
		expirationUnits int
		ptype           byte
		extraData       bool
	}
	pingTests := []test{
		{"Ping-BasicTest(v4001)",
			"Sends a 'ping' from an unknown source, expects a 'pong' back",
			ourAddr,
			targetAddr,
			1,
			PingPacket,
			false},
		{"Ping-SourceUnknownrongTo(v4002)",
			"Does a ping with incorrect 'to', expects a pong back",
			ourAddr,
			badAddr,
			1,
			PingPacket,
			false},
		{"Ping-SourceUnknownWrongFrom(v4003)",
			"Sends a 'ping' with incorrect from field. Expect a valid 'pong' back - a bad 'from' should be ignored",
			badAddr,
			targetAddr,
			1,
			PingPacket,
			false},

		{"Ping-SourceUnknownExtraData(v4004)",
			"Sends a 'ping' with a 'future format' packet containing extra fields. Expects a valid 'pong' back",
			ourAddr,
			targetAddr,
			1,
			PingPacket,
			true},
		{"Ping-SourceUnknownExtraDataWrongFrom(v4005)",
			"Sends 'ping' with a 'future format' packet containing extra fields and make sure it works even with the wrong 'from' field. Expects a valid 'pong' back",
			badAddr,
			targetAddr,
			1,
			PingPacket,
			true},
		{"Ping-SourceUnknownWrongPacketType(v4006)",
			"PingTargetWrongPacketType send a packet (a ping packet, though it could be something else) with an unknown packet type to the client and" +
				"see how the target behaves. Expects the target to not send any kind of response.",
			ourAddr,
			targetAddr,
			1,
			GarbagePacket8,
			false},
		/*
			{"Ping-BondedFromSignatureMismatch(v4009)",
				"Ping node under test, from an already bonded node, but the 'ping' has a bad from-field. " +
					"Expects the target to ignore the bad 'from' and respond with a valid pong.",
				ourAddr,
				targetAddr,
				1},
		*/
		{"Ping-PastExpiration(v4011)",
			"Sends a 'ping' with past expiration, expects no response from the target.",
			ourAddr,
			targetAddr,
			-1,
			PingPacket,
			false},
	}
	// Run tests
	for _, tc := range pingTests {
		req := devp2p.MakePing(tc.fromAddr, tc.toAddr, tc.expirationUnits, tc.extraData)
		t.Log("Ping", req, tc.description)
		if err := v4udp.GenericPing(targetNode.ID(), targetAddr, req, tc.ptype); err != nil {
			t.Error("Failed", tc.name, err)
			//continue
			t.FailNow()
		}
		t.Log("Passed", tc.name)

	}
}
