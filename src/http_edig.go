package main

import (
	"syscall"
	"log"
	"net/http"
	"fmt"
	"strings"
	"encoding/json"
	"github.com/miekg/dns"
	"../src/edig"
)


var ServerList []string = []string{
	"119.29.29.29", // dns pod
	"223.5.5.5", // 阿里
	"223.6.6.6", // 阿里
}

var ServerIndex int = 0 ;

func GetServerIP()(string){

	ServerIndex++
	if ServerIndex > 99999{
		ServerIndex = 0
	}
	return ServerList[ServerIndex % 3]
}

func Query(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	domain := r.Form.Get( "domain" )
	server := r.Form.Get( "server" )
	ip := r.Form.Get("ip")
	ttl := r.Form.Get("ttl")
	format := r.Form.Get("format")
	questType := "miekg/dns"

	if strings.EqualFold( server, "" ){
		server = GetServerIP()
	}


	if strings.EqualFold( ip, "" ) == false{

		digModel, err := edig.EDig( server, domain, ip )

		if err == nil {
			questType = "system/dig"
			digModel, err = edig.CMDDig( server, domain, ip )
		}

		if err != nil{
			fmt.Fprintf(w, "error: " + "domain="+domain + ", server="+server + ", ip="+ip)
			return
		}


		if strings.EqualFold( format, "dns" ){

			body, err := json.Marshal(digModel)
			if err != nil {
				panic(err.Error())
			}
			fmt.Fprintf(w, string(body))

		}else if strings.EqualFold( format, "data" ){

			fmt.Fprintf(w, getData(digModel, ttl))

		}else if strings.EqualFold( format, "debug" ){

			dataStr := fmt.Sprint( "questType:",questType, "\n" , "domain:",domain, "\n" , "server:",server, "\n" , "ip:",ip, "\n" , "format:",format, "\n\n\n\n" , digModel.String() )

			fmt.Fprintf(w, dataStr)

		}else{

			fmt.Fprintf(w, getData(digModel, "false"))

		}

	}

}



func getData(digMidel edig.DIG_MODEL, ttl string)(string){

	data := ""

	for i:=0 ; i<len(digMidel.ANSWER_SECTION) ;i++{
		if digMidel.ANSWER_SECTION[i].TYPE == dns.TypeA{
			data += digMidel.ANSWER_SECTION[i].RESULT + ","
		}
	}

	if strings.EqualFold( ttl, "true" ){
		data += fmt.Sprint(digMidel.ANSWER_SECTION[0].TTL)
	}else{
		data = data[0:len(data)-1]
	}

	return data
}

func main() {

	// 修改文件数
	ulimit()

	// 初始化数据
	fmt.Println( "初始化数据完毕!" )

	// 初始化 路由
	http.HandleFunc("/q", Query )
	fmt.Println( "初始化路由完毕!" )

	fmt.Println( "启动服务器 8053端口" )
	err := http.ListenAndServe(":8053", nil) //设置监听的端口
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}


func ulimit() {

	var rlimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit)
	if err != nil {
		log.Panic("can't modify ulimit", err)
	}
	rlimit.Cur = 655350
	rlimit.Max = 655350
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit)
	if err != nil {
		log.Panic("can't modify ulimit", err)
	}
}