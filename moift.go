package main

import (
	"time"
	"os"
	"log"
	"sort"
	"fmt"
	"regexp"
//	"strconv"

	snmp "github.com/soniah/gosnmp"
)

var oids = map[string]string{
	"ifIndex": "1.3.6.1.2.1.2.2.1.1",
	"ifDescr": "1.3.6.1.2.1.2.2.1.2",
	"ifName":  "1.3.6.1.2.1.31.1.1.1.1",
}

func main() {
	var ip string = "127.0.0.1"
	var community string = "public"
	var err error

	ip = os.Args[1]
	community = os.Args[2]

	target := &snmp.GoSNMP{
		Target: ip,
		Community: community,
		Port: 161,
		Version: snmp.Version2c,
		Timeout: time.Duration(1) * time.Second,
	}

	err = target.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer target.Conn.Close()

	name2index, err := getInterfaces(target, []string{"port1", "ha*"})
	if err != nil {
		log.Fatal(err)
	}

	var ifNames []string
	for ifName := range name2index {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	// for Debug use
	for _, ifName := range ifNames {
		fmt.Println(ifName, name2index[ifName])
	}

}

func getInterfaces(target *snmp.GoSNMP, patterns []string) (map[string]string, error) {
	// patterns should be able to compile
	var compiledPatterns []*regexp.Regexp
	for i:=0; i<len(patterns); i++ {
		compiledPatterns = append(compiledPatterns, regexp.MustCompile(patterns[i]))
	}

	name2index := map[string]string{}
	
	results, err := target.BulkWalkAll(oids["ifName"])
	
	// for sorting interfaces
	var ifNames []string
	for _, pdu := range results {
		// .1.3.6.1.2.1.31.1.1.1.1.<ifindex>
		// <--- 24 characters ---->
		ifName := string(pdu.Value.([]uint8))
		for i:=0; i<len(compiledPatterns); i++ {
			if compiledPatterns[i].MatchString(ifName) {
				ifNames = append(ifNames, ifName)
				name2index[ifName] = pdu.Name[24:]
				break
			}
		}
	}

	return name2index, err
}