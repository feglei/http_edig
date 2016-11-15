package edig

import "fmt"

type DIG_MODEL struct {

	SERVER             string
	DOMAIN             string
	CLIENT_IP          string
	TYPE               uint16

	ANSWER_SECTION     []BASE_MODEL
	AUTHORITY_SECTION  []BASE_MODEL
	ADDITIONAL_SECTION []BASE_MODEL
}

type BASE_MODEL struct {
	DOMAIN string
	TTL    uint32
	TYPE   uint16
	RESULT string
}



func (m *DIG_MODEL) String() (string) {

	str := "---------------------DIG_MODEL STRAT: ---------------------\n\n"

	str += fmt.Sprint("SERVER:", m.SERVER, "\n")
	str += fmt.Sprint("DOMAIN:", m.DOMAIN, "\n")
	str += fmt.Sprint("CLIENT_IP:", m.CLIENT_IP, "\n")
	str += fmt.Sprint("TYPE:", m.TYPE, "\n")

	str += "\n\n"
	str += "ANSWER_SECTION:\n"

	for i := 0; i < len(m.ANSWER_SECTION); i++ {
		str += m.ANSWER_SECTION[i].String()
	}

	str += "\n\n"
	str += "AUTHORITY_SECTION:\n"

	for i := 0; i < len(m.AUTHORITY_SECTION); i++ {
		str += m.AUTHORITY_SECTION[i].String()
	}

	str += "\n\n"
	str += "ADDITIONAL_SECTION:\n"

	for i := 0; i < len(m.ADDITIONAL_SECTION); i++ {
		str += m.ADDITIONAL_SECTION[i].String()
	}

	str += "---------------------DIG_MODEL EDN: ---------------------\n\n"

	return str
}


func (m *BASE_MODEL) String() (string) {

	str := "\n"

	str += fmt.Sprint("DOMAIN:", m.DOMAIN, "\n")
	str += fmt.Sprint("TTL:", m.TTL, "\n")
	str += fmt.Sprint("TYPE:", m.TYPE, "\n")
	str += fmt.Sprint("RESULT:", m.RESULT, "\n")

	return str
}