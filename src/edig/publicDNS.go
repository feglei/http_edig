package edig

import (
	"github.com/miekg/dns"
	"fmt"
	"os"
)

var DEFAULT_RESOLV_FILE = "/etc/resolv.conf"
var conf* dns.ClientConfig


func initDnsList(){

	cf, err := dns.ClientConfigFromFile(DEFAULT_RESOLV_FILE)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}else{

		conf = cf
	}
}

func GetLocalhostDNSServer()(string){
	if conf == nil {
		initDnsList()
	}
	if len(conf.Servers) == 0{
		initDnsList()
	}
	return conf.Servers[0]
}