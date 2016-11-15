package edig


type Parameter struct{

	qtype []uint16
	qclass []uint16
	qname []string
	nameserver string

	short 		bool 	//flag.Bool("short", false, "abbreviate long DNSSEC records")
	dnssec 		bool	//flag.Bool("dnssec", false, "request DNSSEC records")
	query 		bool	//flag.Bool("question", false, "show question")
	check 		bool	//flag.Bool("check", false, "check internal DNSSEC consistency")
	six 		bool	//flag.Bool("6", false, "use IPv6 only")
	four 		bool	//flag.Bool("4", false, "use IPv4 only")
	anchor		string	//flag.String("anchor", "", "use the DNSKEY in this file as trust anchor")
	tsig		string	//flag.String("tsig", "", "request tsig with key: [hmac:]name:key")
	port		int	//flag.Int("port", 53, "port number to use")
	aa		bool	//flag.Bool("aa", false, "set AA flag in query")
	ad		bool	//flag.Bool("ad", false, "set AD flag in query")
	cd		bool	//flag.Bool("cd", false, "set CD flag in query")
	rd		bool	//flag.Bool("rd", true, "set RD flag in query")
	fallback	bool	//flag.Bool("fallback", false, "fallback to 4096 bytes bufsize and after that TCP")
	tcp		bool	//flag.Bool("tcp", false, "TCP mode, multiple queries are asked over the same connection")
	nsid		bool	//flag.Bool("nsid", false, "set edns nsid option")
	client		string	//flag.String("client", "", "set edns client-subnet option")
	clientdraftcode	bool	//flag.Bool("clientdraft", false, "set edns client-subnet option using the draft option code")
	opcode		string	//flag.String("opcode", "query", "set opcode to query|update|notify")
	rcode		string	//flag.String("rcode", "success", "set rcode to noerror|formerr|nxdomain|servfail|...")
	//serial		int	//flag.Int("serial", 0, "perform an IXFR with this serial")
}

func getBaseParameter()(par Parameter){
	par.short = false
	par.dnssec = false
	par.query = false
	par.check = false
	par.six = false
	par.four = false
	par.anchor = ""
	par.tsig = ""
	par.port = 53
	par.aa = false
	par.ad = false
	par.cd = false
	par.rd = false
	par.fallback = false
	par.tcp = false
	par.nsid = false
	par.client = ""
	par.clientdraftcode = false
	par.opcode = "query"
	par.rcode = "success"
	return par
}
