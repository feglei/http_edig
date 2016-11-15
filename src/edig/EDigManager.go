package edig

import (
	"github.com/miekg/dns"
	"strings"
	"os/exec"
	"errors"
	"strconv"
	"fmt"
)

//var digPath = "./res/edig_mac"
var digPath = "./res/edig_centos"

func CMDDig(server string, domain string, clientIp string)( tempDigModel DIG_MODEL, err error ) {

	tempDigModel.SERVER = server
	tempDigModel.DOMAIN = domain
	tempDigModel.CLIENT_IP = clientIp
	tempDigModel.TYPE = dns.TypeA

	outStr := ""

	if strings.EqualFold( server , "" ) {
		outStr = Command(digPath, domain, getTypeStr(tempDigModel.TYPE), fmt.Sprint("+client=", clientIp))
	}else{
		outStr = Command(digPath, fmt.Sprint("@", tempDigModel.SERVER), domain, getTypeStr(tempDigModel.TYPE), fmt.Sprint("+client=", clientIp))
	}

	//fmt.Println( outStr )

	if len(outStr) < 10{
		return DIG_MODEL{}, errors.New( "cmd dig error 无返回结果" )
	}

	ANSWER_SECTION_ACCESS, ANSWER_SECTION_RES := getANSWER_SECTION(outStr)
	if ANSWER_SECTION_ACCESS == true {
		tempDigModel.ANSWER_SECTION = ANSWER_SECTION_RES
	}
	AUTHORITY_SECTION_ACCESS, AUTHORITY_SECTION_RES := getAUTHORITY_SECTION(outStr)
	if AUTHORITY_SECTION_ACCESS == true {
		tempDigModel.AUTHORITY_SECTION = AUTHORITY_SECTION_RES
	}
	ADDITIONAL_SECTION_ACCESS, ADDITIONAL_SECTION_RES := getADDITIONAL_SECTION(outStr)
	if ADDITIONAL_SECTION_ACCESS == true {
		tempDigModel.ADDITIONAL_SECTION = ADDITIONAL_SECTION_RES
	}


	if len(tempDigModel.ANSWER_SECTION) == 0{
		return tempDigModel, nil
	}
	// 如果结果是A记录, 直接返回即可。
	if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeA {
		return tempDigModel, nil
	}


	// 返回的是CNAME 循环查询A记录
	for ; ; {

		if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeCNAME{

			// SOA
			tempDigModel.SERVER = ""
			tempDigModel.DOMAIN = tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].RESULT
			tempDigModel.TYPE = dns.TypeSOA

			outStr = Command( digPath, tempDigModel.DOMAIN, getTypeStr(tempDigModel.TYPE) ) //, fmt.Sprint("+client=", clientIp)
			ANSWER_SECTION_ACCESS, ANSWER_SECTION_RES := getANSWER_SECTION(outStr)
			if ANSWER_SECTION_ACCESS == true {
				tempDigModel.ANSWER_SECTION = ANSWER_SECTION_RES
			}

			AUTHORITY_SECTION_ACCESS, AUTHORITY_SECTION_RES := getAUTHORITY_SECTION(outStr)
			if AUTHORITY_SECTION_ACCESS == true {
				tempDigModel.AUTHORITY_SECTION = AUTHORITY_SECTION_RES
			}

			ADDITIONAL_SECTION_ACCESS, ADDITIONAL_SECTION_RES := getADDITIONAL_SECTION(outStr)
			if ADDITIONAL_SECTION_ACCESS == true {
				tempDigModel.ADDITIONAL_SECTION = ADDITIONAL_SECTION_RES
			}


			if len(tempDigModel.AUTHORITY_SECTION) > 0{
				tempDigModel.SERVER = tempDigModel.AUTHORITY_SECTION[0].RESULT
			}
			if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeSOA{
				tempDigModel.SERVER  = tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].RESULT
			}
			if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeCNAME{
				tempDigModel.DOMAIN = tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].RESULT
			}

			tempDigModel.TYPE = dns.TypeA

			// A
			//fmt.Println(tempDigModel)
			outStr := Command(digPath, fmt.Sprint("@", tempDigModel.SERVER), tempDigModel.DOMAIN, getTypeStr(tempDigModel.TYPE), fmt.Sprint("+client=", clientIp))

			ANSWER_SECTION_ACCESS, ANSWER_SECTION_RES = getANSWER_SECTION(outStr)
			if ANSWER_SECTION_ACCESS == true {
				tempDigModel.ANSWER_SECTION = ANSWER_SECTION_RES
			}

			AUTHORITY_SECTION_ACCESS, AUTHORITY_SECTION_RES = getAUTHORITY_SECTION(outStr)
			if AUTHORITY_SECTION_ACCESS == true {
				tempDigModel.AUTHORITY_SECTION = AUTHORITY_SECTION_RES
			}

			ADDITIONAL_SECTION_ACCESS, ADDITIONAL_SECTION_RES = getADDITIONAL_SECTION(outStr)
			if ADDITIONAL_SECTION_ACCESS == true {
				tempDigModel.ADDITIONAL_SECTION = ADDITIONAL_SECTION_RES
			}

		}

		// 循环查询是否是A记录, 是A记录退出循环
		if tempDigModel.ANSWER_SECTION[len(tempDigModel.ANSWER_SECTION)-1].TYPE == dns.TypeA{
			break
		}
	}


	return tempDigModel, err

}

func Command(name string, arg ...string)(string){

	//fmt.Println( name, arg  )

	cmd := exec.Command(name, arg...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("错误 Error:", err)
		//panic(err)
		return ""
	}

	//fmt.Println( string(out) )

	return string(out)
}

func getANSWER_SECTION(res string) (bool, []BASE_MODEL) {
	var ANSWER_SECTION_STR = ";; ANSWER SECTION:\n"
	return getBaseModel(res, ANSWER_SECTION_STR)
}

func getAUTHORITY_SECTION(res string) (bool, []BASE_MODEL) {
	var AUTHORITY_SECTION_STR = ";; AUTHORITY SECTION:\n"
	return getBaseModel(res, AUTHORITY_SECTION_STR)
}

func getADDITIONAL_SECTION(res string) (bool, []BASE_MODEL) {
	var ADDITIONAL_SECTION_STR = ";; ADDITIONAL SECTION:\n"
	return getBaseModel(res, ADDITIONAL_SECTION_STR)
}

func getBaseModel(res, BODY string) (bool, []BASE_MODEL) {
	startIndex := strings.Index(res, BODY)
	if startIndex == -1 {
		return false, nil
	}
	temp_str := res[ startIndex : len(res) ]
	stopIndex := strings.Index(temp_str, "\n\n")
	if stopIndex == -1 {
		return false, nil
	}
	ANSWER_STR := temp_str[len(BODY):stopIndex ]
	temp_arr := strings.Split(ANSWER_STR, "\n")
	if len(temp_arr) == 0 {
		return false, nil
	}
	base_model := make([]BASE_MODEL, len(temp_arr))
	for i := 0; i < len(temp_arr); i++ {
		arr := strings.Fields(temp_arr[i])
		if len(arr) < 5 {
			return false, nil
		}

		ttl_temp, _ := strconv.ParseInt(arr[1], 32, 0)
		base_model[i] = BASE_MODEL{arr[0], uint32(ttl_temp), getTypeInt(arr[3]), arr[4] }
	}
	return true, base_model
}

func getTypeStr(t uint16)(string){
	switch (t) {
	case dns.TypeA:
		return "A"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeNS:
		return "NS"
	case dns.TypeSOA:
		return "SOA"
	}
	return ""
}

func getTypeInt(t string)(uint16){
	if strings.EqualFold( t,"a" ) || strings.EqualFold( t,"A" ){
		return dns.TypeA
	} else if strings.EqualFold( t,"cname" ) || strings.EqualFold( t,"CNAME" ){
		return dns.TypeCNAME
	} else if strings.EqualFold( t,"ns" ) || strings.EqualFold( t,"NS" ){
		return dns.TypeNS
	} else if strings.EqualFold( t,"soa" ) || strings.EqualFold( t,"SOA" ){
		return dns.TypeSOA
	}
	return uint16(0)
}