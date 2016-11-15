package edig

import (
	"github.com/miekg/dns"
	"strings"
	"time"
	"fmt"
	"os"
	"flag"
	"strconv"
	"net"
	"errors"
)

var dnskey *dns.DNSKEY


func EDig(server string, domain string, clientIp string)( tempDigModel DIG_MODEL, err error ) {


	tempDigModel, err = dig(server, domain, clientIp, dns.TypeA)
	if err != nil || len(tempDigModel.ADDITIONAL_SECTION) == 0 {
		return tempDigModel , err
	}
	// 如果结果是A记录, 直接返回即可。
	if tempDigModel.ADDITIONAL_SECTION[len(tempDigModel.ADDITIONAL_SECTION)-1].TYPE == dns.TypeA{

		return tempDigModel , err
	}


	// 返回的是CNAME 循环查询A记录
	for ;; {

		if len(tempDigModel.ANSWER_SECTION) == 0 {
			return tempDigModel, errors.New( "ANSWER_SECTION is nil" )
		}

		if tempDigModel.ANSWER_SECTION[ len(tempDigModel.ANSWER_SECTION)-1 ].TYPE == dns.TypeCNAME{

			// SOA
			tempDigModel.SERVER = ""
			tempDigModel.DOMAIN = tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].RESULT
			tempDigModel.TYPE = dns.TypeSOA

			cname , soa , ns := findSoaNs(tempDigModel.DOMAIN)


			if strings.EqualFold( cname , "")  == false{
				cname = strings.TrimRight(cname, ",")
				tempArr := strings.Split( cname ,"," )
				tempDigModel.DOMAIN = tempArr[len(tempArr)-1]
			}
			if strings.EqualFold( soa , "")  == false {
				soa = strings.TrimRight(soa, ",")
				tempArr := strings.Split( soa ,"," )
				if len( tempArr ) > 0{
					tempDigModel.SERVER = tempArr[len(tempArr)-1]
				}
			}

			if strings.EqualFold( ns , "")  == false {
				ns = strings.TrimRight(ns, ",")
				tempArr := strings.Split(ns, ",")
				if strings.EqualFold( tempDigModel.SERVER, "" ){
					tempDigModel.SERVER = tempArr[len(tempArr)-1]
				}
			}

			tempDigModel, err = dig(tempDigModel.SERVER, tempDigModel.DOMAIN, tempDigModel.CLIENT_IP, dns.TypeA)

			//fmt.Println( tempDigModel, err )

		}

		// 循环查询是否是A记录, 是A记录退出循环
		if len(tempDigModel.ANSWER_SECTION) == 0{
			return tempDigModel, errors.New("edns err")
		}
		if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeA {
			return
		}
	}

	return tempDigModel, err
}


func dig( server string, domain string, clientIp string, qtype uint16)(digModel DIG_MODEL, err error){

	//fmt.Println( "server=",server,  "   domain=",domain,  "   clientIp=",clientIp,   "   qtype=",qtype )

	par := getBaseParameter()
	par.nameserver = server
	par.client = clientIp
	par.qname = []string{ domain }
	par.qtype = []uint16{ qtype }
	par.qclass = []uint16{ dns.ClassINET }

	digModel , err = digParameterAll(par)

	//fmt.Println( "digModel= ",digModel.String() )
	return digModel , err
}



func digParameterAll( para Parameter )(digModel DIG_MODEL, err error){

	//fmt.Println( para )

	if para.anchor != "" {
		f, err := os.Open(para.anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failure to open %s: %s\n", para.anchor, err.Error())
		}
		r, err := dns.ReadRR(f, para.anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failure to read an RR from %s: %s\n", para.anchor, err.Error())
		}
		if k, ok := r.(*dns.DNSKEY); !ok {
			fmt.Fprintf(os.Stderr, "No DNSKEY read from %s\n", para.anchor)
		} else {
			dnskey = k
		}
	}

	//var nameserver string

	Flags:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			para.nameserver = flag.Arg(i)
			continue Flags
		}
		// First class, then type, to make ANY queries possible
		// And if it looks like type, it is a type
		if k, ok := dns.StringToType[strings.ToUpper(flag.Arg(i))]; ok {
			para.qtype = append(para.qtype, k)
			continue Flags
		}
		// If it looks like a class, it is a class
		if k, ok := dns.StringToClass[strings.ToUpper(flag.Arg(i))]; ok {
			para.qclass = append(para.qclass, k)
			continue Flags
		}
		// If it starts with TYPExxx it is unknown rr
		if strings.HasPrefix(flag.Arg(i), "TYPE") {
			i, e := strconv.Atoi(string([]byte(flag.Arg(i))[4:]))
			if e == nil {
				para.qtype = append(para.qtype, uint16(i))
				continue Flags
			}
		}
		// If it starts with CLASSxxx it is unknown class
		if strings.HasPrefix(flag.Arg(i), "CLASS") {
			i, e := strconv.Atoi(string([]byte(flag.Arg(i))[5:]))
			if e == nil {
				para.qclass = append(para.qclass, uint16(i))
				continue Flags
			}
		}
		// Anything else is a qname
		para.qname = append(para.qname, flag.Arg(i))
	}
	if len(para.qname) == 0 {
		para.qname = []string{"."}
		if len(para.qtype) == 0 {
			para.qtype = append(para.qtype, dns.TypeNS)
		}
	}
	if len(para.qtype) == 0 {
		para.qtype = append(para.qtype, dns.TypeA)
	}
	if len(para.qclass) == 0 {
		para.qclass = append(para.qclass, dns.ClassINET)
	}

	if len(para.nameserver) == 0 {
		para.nameserver = GetLocalhostDNSServer()
	}

	if strings.EqualFold( para.nameserver[len(para.nameserver)-1:len(para.nameserver)] , "." ) {
		para.nameserver = para.nameserver[0:len(para.nameserver)-1]
	}

	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name

	if para.nameserver[0] == '[' && para.nameserver[len(para.nameserver)-1] == ']' {
		para.nameserver = para.nameserver[1 : len(para.nameserver)-1]
	}
	if i := net.ParseIP(para.nameserver); i != nil {
		para.nameserver = net.JoinHostPort(para.nameserver, strconv.Itoa(para.port))
	} else {
		para.nameserver = dns.Fqdn(para.nameserver) + ":" + strconv.Itoa(para.port)
	}
	c := new(dns.Client)
	t := new(dns.Transfer)
	c.Net = "udp"
	if para.four {
		c.Net = "udp4"
	}
	if para.six {
		c.Net = "udp6"
	}
	if para.tcp {
		c.Net = "tcp"
		if para.four {
			c.Net = "tcp4"
		}
		if para.six {
			c.Net = "tcp6"
		}
	}

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = para.aa
	m.MsgHdr.AuthenticatedData = para.ad
	m.MsgHdr.CheckingDisabled = para.cd
	m.MsgHdr.RecursionDesired = para.rd
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	if op, ok := dns.StringToOpcode[strings.ToUpper(para.opcode)]; ok {
		m.Opcode = op
	}
	m.Rcode = dns.RcodeSuccess
	if rc, ok := dns.StringToRcode[strings.ToUpper(para.rcode)]; ok {
		m.Rcode = rc
	}

	if para.dnssec || para.nsid || para.client != "" {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		if para.dnssec {
			o.SetDo()
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if para.nsid {
			e := new(dns.EDNS0_NSID)
			e.Code = dns.EDNS0NSID
			o.Option = append(o.Option, e)
			// NSD will not return nsid when the udp message size is too small
			o.SetUDPSize(dns.DefaultMsgSize)
		}
		if para.client != "" {
			e := new(dns.EDNS0_SUBNET)
			e.Code = dns.EDNS0SUBNET
			if para.clientdraftcode {
				e.DraftOption = true
			}
			e.SourceScope = 0
			e.Address = net.ParseIP(para.client)
			if e.Address == nil {
				fmt.Fprintf(os.Stderr, "Failure to parse IP address: %s\n", para.client)
				return
			}
			e.Family = 1 // IP4
			e.SourceNetmask = net.IPv4len * 8
			if e.Address.To4() == nil {
				e.Family = 2 // IP6
				e.SourceNetmask = net.IPv6len * 8
			}
			o.Option = append(o.Option, e)
		}
		m.Extra = append(m.Extra, o)
	}
	if para.tcp {
		co := new(dns.Conn)
		tcp := "tcp"
		if para.six {
			tcp = "tcp6"
		}

		if co.Conn, err = net.DialTimeout(tcp, para.nameserver, 2*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "Dialing "+para.nameserver+" failed: "+err.Error()+"\n")
			return
		}
		defer co.Close()
		qt := dns.TypeA
		qc := uint16(dns.ClassINET)
		for i, v := range para.qname {
			if i < len(para.qtype) {
				qt = para.qtype[i]
			}
			if i < len(para.qclass) {
				qc = para.qclass[i]
			}
			m.Question[0] = dns.Question{dns.Fqdn(v), qt, qc}
			m.Id = dns.Id()
			if para.tsig != "" {
				if algo, name, secret, ok := tsigKeyParse(para.tsig); ok {
					m.SetTsig(name, algo, 300, time.Now().Unix())
					c.TsigSecret = map[string]string{name: secret}
					t.TsigSecret = map[string]string{name: secret}
				} else {
					fmt.Fprintf(os.Stderr, ";; TSIG key data error\n")
					continue
				}
			}
			co.SetReadDeadline(time.Now().Add(2 * time.Second))
			co.SetWriteDeadline(time.Now().Add(2 * time.Second))

			if para.query {
				fmt.Printf("%s", m.String())
				fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
			}
			then := time.Now()
			if e := co.WriteMsg(m); e != nil {
				fmt.Fprintf(os.Stderr, ";; %s\n", e.Error())
				continue
			}
			r, e := co.ReadMsg()
			if e != nil {
				fmt.Fprintf(os.Stderr, ";; %s\n", e.Error())
				continue
			}
			time.Since(then) //rtt := time.Since(then)
			if r.Id != m.Id {
				fmt.Fprintf(os.Stderr, "Id mismatch\n")
				continue
			}

			if para.check {
				sigCheck(r, para.nameserver, true)
				denialCheck(r)
				fmt.Println()
			}
			if para.short {
				r = shortMsg(r)
			}

			//fmt.Printf("%v", r)
			//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, para.nameserver, tcp, r.Len())
		}
		return
	}

	qt := dns.TypeA
	qc := uint16(dns.ClassINET)

	Query:
	for i, v := range para.qname {
		if i < len(para.qtype) {
			qt = para.qtype[i]
		}
		if i < len(para.qclass) {
			qc = para.qclass[i]
		}
		m.Question[0] = dns.Question{dns.Fqdn(v), qt, qc}
		m.Id = dns.Id()
		if para.tsig != "" {
			if algo, name, secret, ok := tsigKeyParse(para.tsig); ok {
				m.SetTsig(name, algo, 3000, time.Now().Unix())
				c.TsigSecret = map[string]string{name: secret}
				t.TsigSecret = map[string]string{name: secret}
			} else {
				fmt.Fprintf(os.Stderr, "TSIG key data error\n")
				continue
			}
		}
		if para.query {
			fmt.Printf("%s", m.String())
			fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
		}
		if qt == dns.TypeAXFR || qt == dns.TypeIXFR {
			env, err := t.In(m, para.nameserver)
			if err != nil {
				fmt.Printf(";; %s\n", err.Error())
				continue
			}
			envelope := 0
			record := 0
			for e := range env {
				if e.Error != nil {
					fmt.Printf(";; %s\n", e.Error.Error())
					continue Query
				}
				for _, r := range e.RR {
					fmt.Printf("%s\n", r)
				}
				record += len(e.RR)
				envelope++
			}
			fmt.Printf("\n;; xfr size: %d records (envelopes %d)\n", record, envelope)
			continue
		}
		r, rtt, e := c.Exchange(m, para.nameserver)//r, rtt, e := c.Exchange(m, nameserver)
		Redo:
		if e != nil {
			//fmt.Printf(";; %s\n", e.Error())
			err = e
			continue
		}
		if r.Id != m.Id {
			fmt.Fprintf(os.Stderr, "Id mismatch\n")
			return digModel, err
		}
		if r.MsgHdr.Truncated && para.fallback {
			if !para.dnssec {
				fmt.Printf(";; Truncated, trying %d bytes bufsize\n", dns.DefaultMsgSize)
				o := new(dns.OPT)
				o.Hdr.Name = "."
				o.Hdr.Rrtype = dns.TypeOPT
				o.SetUDPSize(dns.DefaultMsgSize)
				m.Extra = append(m.Extra, o)
				r, rtt, e = c.Exchange(m, para.nameserver)
				para.dnssec = true
				goto Redo
			} else {
				// First EDNS, then TCP
				fmt.Printf(";; Truncated, trying TCP\n")
				c.Net = "tcp"
				r, rtt, e = c.Exchange(m, para.nameserver)
				goto Redo
			}
		}
		if r.MsgHdr.Truncated && !para.fallback {
			fmt.Printf(";; Truncated\n")
		}
		if para.check {
			sigCheck(r, para.nameserver, para.tcp)
			denialCheck(r)
			fmt.Println()
		}
		if para.short {
			r = shortMsg(r)
		}

		if err != nil{
			fmt.Println( "r=",r, "rtt=",rtt )
		}


		getBase := func(temp_rr []dns.RR)(base []BASE_MODEL) {
			base = make( []BASE_MODEL, len(temp_rr) )
			temp_base := BASE_MODEL{}
			for i := 0 ; i < len(temp_rr); i++{
				temp_base.TYPE = temp_rr[i].Header().Rrtype
				temp_base.TTL = temp_rr[i].Header().Ttl
				switch temp_base.TYPE {
					case dns.TypeCNAME:
						temp_cname := temp_rr[i].(*dns.CNAME)
						temp_base.RESULT = temp_cname.Target

						break
					case dns.TypeA:
						temp_a := temp_rr[i].(*dns.A)
						temp_base.RESULT = temp_a.A.String()
						break
					case dns.TypeNS:
						temp_ns := temp_rr[i].(*dns.NS)
						temp_base.RESULT = temp_ns.Ns
						break
					case dns.TypeSOA:
						temp_soa := temp_rr[i].(*dns.SOA)
						temp_base.RESULT = temp_soa.Ns
						break
				}

				base[i] = temp_base
			}
			return base
		}


		digModel.SERVER = para.nameserver
		digModel.DOMAIN = para.qname[0]
		digModel.CLIENT_IP = para.client
		digModel.TYPE = para.qtype[0]
		digModel.ANSWER_SECTION = getBase(r.Answer)
		digModel.AUTHORITY_SECTION = getBase(r.Ns)
		digModel.ADDITIONAL_SECTION = getBase(r.Extra)

		//fmt.Println(r.Answer)
		//fmt.Printf("%v", r)
		//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, r.Len())

	}


	return digModel, err
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func tsigKeyParse(s string) (algo, name, secret string, ok bool) {
	s1 := strings.SplitN(s, ":", 3)
	switch len(s1) {
	case 2:
		return "hmac-md5.sig-alg.reg.int.", dns.Fqdn(s1[0]), s1[1], true
	case 3:
		switch s1[0] {
		case "hmac-md5":
			return "hmac-md5.sig-alg.reg.int.", dns.Fqdn(s1[1]), s1[2], true
		case "hmac-sha1":
			return "hmac-sha1.", dns.Fqdn(s1[1]), s1[2], true
		case "hmac-sha256":
			return "hmac-sha256.", dns.Fqdn(s1[1]), s1[2], true
		}
	}
	return
}

func sectionCheck(set []dns.RR, server string, tcp bool) {
	var key *dns.DNSKEY
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			expired := ""
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if dnskey == nil {
				key = getKey(rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag, server, tcp)
			} else {
				key = dnskey
			}
			if key == nil {
				fmt.Printf(";? DNSKEY %s/%d not found\n", rr.(*dns.RRSIG).SignerName, rr.(*dns.RRSIG).KeyTag)
				continue
			}
			where := "net"
			if dnskey != nil {
				where = "disk"
			}
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf(";- Bogus signature, %s does not validate (DNSKEY %s/%d/%s) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where, err.Error(), expired)
			} else {
				fmt.Printf(";+ Secure signature, %s validates (DNSKEY %s/%d/%s) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), where, expired)
			}
		}
	}
}

// Check the sigs in the msg, get the signer's key (additional query), get the
// rrset from the message, check the signature(s)
func sigCheck(in *dns.Msg, server string, tcp bool) {
	sectionCheck(in.Answer, server, tcp)
	sectionCheck(in.Ns, server, tcp)
	sectionCheck(in.Extra, server, tcp)
}

// Check if there is need for authenticated denial of existence check
func denialCheck(in *dns.Msg) {
	denial := make([]dns.RR, 0)
	// nsec(3) live in the auth section
	nsec := false
	nsec3 := false
	for _, rr := range in.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			denial = append(denial, rr)
			nsec = true
			continue
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			denial = append(denial, rr)
			nsec3 = true
			continue
		}
	}
	if nsec && nsec3 {
		// What??! Both NSEC and NSEC3 in there?
		return
	}
	if nsec3 {
		denial3(denial, in)
		return
	}
	if nsec {
		return
	}
}

// NSEC3 Helper
func denial3(nsec3 []dns.RR, in *dns.Msg) {
	qname := in.Question[0].Name
	qtype := in.Question[0].Qtype
	switch in.Rcode {
	case dns.RcodeSuccess:
		// qname should match nsec3, type should not be in bitmap
		match := nsec3[0].(*dns.NSEC3).Match(qname)
		if !match {
			fmt.Printf(";- Denial, owner name does not match qname\n")
			fmt.Printf(";- Denial, failed authenticated denial of existence proof for no data\n")
			return
		}
		for _, t := range nsec3[0].(*dns.NSEC3).TypeBitMap {
			if t == qtype {
				fmt.Printf(";- Denial, found type, %d, in bitmap\n", qtype)
				fmt.Printf(";- Denial, failed authenticated denial of existence proof for no data\n")
				return
			}
			if t > qtype { // ordered list, bail out, because not found
				break
			}
		}
		// Some success data printed here
		fmt.Printf(";+ Denial, matching record, %s, (%s) found and type %s denied\n", qname,
			strings.ToLower(dns.HashName(qname, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)),
			dns.TypeToString[qtype])
		fmt.Printf(";+ Denial, secure authenticated denial of existence proof for no data\n")
		return
	case dns.RcodeNameError: // NXDOMAIN Proof
		indx := dns.Split(qname)
		ce := "" // Closest Encloser
		nc := "" // Next Closer
		wc := "" // Source of Synthesis (wildcard)
		ClosestEncloser:
		for i := 0; i < len(indx); i++ {
			for j := 0; j < len(nsec3); j++ {
				if nsec3[j].(*dns.NSEC3).Match(qname[indx[i]:]) {
					ce = qname[indx[i]:]
					wc = "*." + ce
					if i == 0 {
						nc = qname
					} else {
						nc = qname[indx[i-1]:]
					}
					break ClosestEncloser
				}
			}
		}
		if ce == "" {
			fmt.Printf(";- Denial, closest encloser not found\n")
			return
		}
		fmt.Printf(";+ Denial, closest encloser, %s (%s)\n", ce,
			strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
		covered := 0 // Both nc and wc must be covered
		for i := 0; i < len(nsec3); i++ {
			if nsec3[i].(*dns.NSEC3).Cover(nc) {
				fmt.Printf(";+ Denial, next closer %s (%s), covered by %s -> %s\n", nc, nsec3[i].Header().Name, nsec3[i].(*dns.NSEC3).NextDomain,
					strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
				covered++
			}
			if nsec3[i].(*dns.NSEC3).Cover(wc) {
				fmt.Printf(";+ Denial, source of synthesis %s (%s), covered by %s -> %s\n", wc, nsec3[i].Header().Name, nsec3[i].(*dns.NSEC3).NextDomain,
					strings.ToLower(dns.HashName(ce, nsec3[0].(*dns.NSEC3).Hash, nsec3[0].(*dns.NSEC3).Iterations, nsec3[0].(*dns.NSEC3).Salt)))
				covered++
			}
		}
		if covered != 2 {
			fmt.Printf(";- Denial, too many, %d, covering records\n", covered)
			fmt.Printf(";- Denial, failed authenticated denial of existence proof for name error\n")
			return
		}
		fmt.Printf(";+ Denial, secure authenticated denial of existence proof for name error\n")
		return
	}
}

// Return the RRset belonging to the signature with name and type t
func getRRset(l []dns.RR, name string, t uint16) []dns.RR {
	l1 := make([]dns.RR, 0)
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

// Get the key from the DNS (uses the local resolver) and return them.
// If nothing is found we return nil
func getKey(name string, keytag uint16, server string, tcp bool) *dns.DNSKEY {
	c := new(dns.Client)
	if tcp {
		c.Net = "tcp"
	}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeDNSKEY)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil
	}
	for _, k := range r.Answer {
		if k1, ok := k.(*dns.DNSKEY); ok {
			if k1.KeyTag() == keytag {
				return k1
			}
		}
	}
	return nil
}

// shorten RRSIG to "miek.nl RRSIG(NS)"
func shortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

// Walk trough message and short Key data and Sig data
func shortMsg(in *dns.Msg) *dns.Msg {
	for i := 0; i < len(in.Answer); i++ {
		in.Answer[i] = shortRR(in.Answer[i])
	}
	for i := 0; i < len(in.Ns); i++ {
		in.Ns[i] = shortRR(in.Ns[i])
	}
	for i := 0; i < len(in.Extra); i++ {
		in.Extra[i] = shortRR(in.Extra[i])
	}
	return in
}

func shortRR(r dns.RR) dns.RR {
	switch t := r.(type) {
	case *dns.DS:
		t.Digest = "..."
	case *dns.DNSKEY:
		t.PublicKey = "..."
	case *dns.RRSIG:
		t.Signature = "..."
	case *dns.NSEC3:
		t.Salt = "." // Nobody cares
		if len(t.TypeBitMap) > 5 {
			t.TypeBitMap = t.TypeBitMap[1:5]
		}
	}
	return r
}







func findSoaNs(domain string) (string, string, string){

	var cname string
	var soa string
	var ns string

	add := func(c, s ,n string) () {
		cname += c
		soa += s
		ns += n
		return
	}

	cname += domain + ","
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)

	m1.Question[0] = dns.Question{domain , dns.TypeSOA, dns.ClassINET}

	server := GetLocalhostDNSServer()

	in, err := dns.Exchange(m1, (server+":53") )
	if err != nil{
		return "" , "" , ""
	}

	rrList := [...][]dns.RR{in.Answer , in.Ns , in.Extra}


	for _, rr := range rrList{
		for i := len(rr)-1 ; i >= 0 ; i--{
			switch rr[i].Header().Rrtype {
			case dns.TypeCNAME:
				temp_cname := rr[i].(*dns.CNAME)
				add(findSoaNs(temp_cname.Target))
				//				fmt.Println(  "temp_cname:" , temp_cname )
				return cname , soa, ns
				break
			case dns.TypeNS:
				temp_ns := rr[i].(*dns.NS)
				ns += temp_ns.Ns + ","// + "|" +  fmt.Sprint( temp_ns.Hdr.Ttl ) + ","
				//				fmt.Println(  "temp_ns:" , temp_ns )
				break
			case dns.TypeSOA:
				temp_soa := rr[i].(*dns.SOA)
				soa += temp_soa.Ns + ","// + "|" + fmt.Sprint( temp_soa.Hdr.Ttl ) + ","
				//				fmt.Println( "temp_soa:" , temp_soa )
				break
			}
		}
	}

	return cname , soa , ns
}