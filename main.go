package main

import (
	"encoding/binary"
	"flag"
	"math/rand"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

type TCP struct {
	srcIPAddr, dstIPAddr                 net.IP
	srcPort, dstPort                     uint16
	seq, ack                             uint32
	dataoffsetAndReservedAndControlFlags uint16
	windowsize, checksum, urgentpointer  uint16
	optionAndPadding                     uint32
}

func NewTCP(srcIPAddr, dstIPAddr net.IP, srcPort, dstPort uint16) *TCP {
	return &TCP{
		srcIPAddr:                            srcIPAddr.To4(),
		dstIPAddr:                            dstIPAddr.To4(),
		srcPort:                              srcPort,
		dstPort:                              dstPort,
		dataoffsetAndReservedAndControlFlags: 0x6002,
		windowsize:                           1024,
		urgentpointer:                        0,
		optionAndPadding:                     0x020405b4 << 4,
	}
}

func (t *TCP) Encode() []byte {
	b := make([]byte, 24)
	// source port
	binary.BigEndian.PutUint16(b[0:2], t.srcPort)
	// destination port
	binary.BigEndian.PutUint16(b[2:4], t.dstPort)
	// sequence number
	binary.BigEndian.PutUint32(b[4:8], t.seq)
	// ack number
	binary.BigEndian.PutUint32(b[8:12], t.ack)
	// dataoffset and reserved(by 0) and control flags
	binary.BigEndian.PutUint16(b[12:14], uint16(t.dataoffsetAndReservedAndControlFlags))
	// window size
	binary.BigEndian.PutUint16(b[14:16], t.windowsize)
	// check sum put after all fileds put
	binary.BigEndian.PutUint16(b[16:18], t.checksum)
	// urgent pointer
	binary.BigEndian.PutUint16(b[18:20], t.urgentpointer)
	// option and padding, type is 2 length is 4 mss is 1460(0x05b4)
	// padding is 4bit
	binary.BigEndian.PutUint32(b[20:24], t.optionAndPadding)
	// checksum recalcurate
	t.checksum = t.calChecksum(b)
	binary.BigEndian.PutUint16(b[16:18], t.checksum)
	return b
}

func (t *TCP) calChecksum(bytes []byte) uint16 {
	checksum := t.pseudoChecksum()
	checksum += 6
	checksum += uint32(len(bytes)) & 0xffff
	checksum += uint32(len(bytes)) >> 16
	length := len(bytes) - 1
	for i := 0; i < length; i += 2 {
		checksum += uint32(bytes[i]) << 8
		checksum += uint32(bytes[i+1])
	}
	if length%2 == 1 {
		checksum += uint32(bytes[length]) << 8
	}
	for checksum > 0xffff {
		checksum = (checksum >> 16) + (checksum & 0xffff)
	}

	return ^uint16(checksum)
}

func (t *TCP) pseudoChecksum() (checksum uint32) {
	//           |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
	// srcIPAddr |       0       |       1       |       2       |       3       |
	// dstIPAddr |       0       |       1       |       2       |       3       |
	checksum += (uint32(t.srcIPAddr[0]) + uint32(t.srcIPAddr[2])) << 8
	checksum += (uint32(t.srcIPAddr[1]) + uint32(t.srcIPAddr[3]))
	checksum += (uint32(t.dstIPAddr[0]) + uint32(t.dstIPAddr[2])) << 8
	checksum += (uint32(t.dstIPAddr[1]) + uint32(t.dstIPAddr[3]))
	return checksum
}

func main() {
	host := flag.String("host", "", "dst address")
	port := flag.Int("port", 0, "dst [prt")
	flag.Parse()
	if *host == "" || *port == 0 {
		flag.Usage()
		return
	}

	srcIPAddr := getRandPublicIP()

	srcPort, err := getSrcTCPPort()
	if err != nil {
		panic(err)
	}

	dstIPAddr := net.ParseIP(*host)
	dstPort := *port

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		panic(err)
	}
	defer func() {
		syscall.Close(fd)
	}()

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		panic(err)
	}

	var addrByteArray [4]byte
	if err != nil {
		panic(err)
	}
	copy(addrByteArray[:], dstIPAddr.To4())
	addr := &syscall.SockaddrInet4{
		Port: dstPort,
		Addr: addrByteArray,
	}

	tcpHeaderBytes := NewTCP(srcIPAddr.To4(), dstIPAddr.To4(), uint16(srcPort), uint16(dstPort)).Encode()
	ipv4HeaderBytes, err := ipv4Header(srcIPAddr, dstIPAddr, len(tcpHeaderBytes)).Marshal()
	if err != nil {
		panic(err)
	}

	if err := syscall.Sendto(
		fd,
		append(ipv4HeaderBytes, tcpHeaderBytes...),
		0,
		addr,
	); err != nil {
		panic(err)
	}
}

func ipv4Header(srcIPAddr, dstIPAddr net.IP, dataLen int) *ipv4.Header {
	return &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + dataLen,
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Src:      srcIPAddr.To4(),
		Dst:      dstIPAddr.To4(),
	}
}

func getSrcTCPPort() (int, error) {

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func getRandPublicIP() net.IP {
	ip := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(ip[0:], uint32(rand.Intn(1<<32-1)))
	if ip[0] == 10 || (ip[0] == 172 && ip[1] == 16) || (ip[0] == 192 && ip[1] == 168) || (ip[0] == 169 && ip[1] == 254) {
		return getRandPublicIP()
	}
	return ip
}
