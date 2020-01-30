package main

import (
	"os/exec"
	"os"
	"log"
	"runtime"
	"sort"
	"fmt"
	"regexp"
	"time"
	"errors"
	"strconv"
	"strings"

	snmp "github.com/soniah/gosnmp"
)

var oids = map[string]string{
	"ifIndex": "1.3.6.1.2.1.2.2.1.1",
	"ifDescr": "1.3.6.1.2.1.2.2.1.2",
	"ifName":  "1.3.6.1.2.1.31.1.1.1.1",
	"ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
	"ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
	"ifXEntry": "1.3.6.1.2.1.31.1.1.1",
}

type ifXEntry struct {
	ifName string
	ifHCInOctets uint64
	ifHCOutOctets uint64
}

func main() {

	type Traffic struct {
		In uint64
		Out uint64
	}

	var ip string = "127.0.0.1"
	var community string = "public"
	var err error
	var interval = 2
	var patterns = []string{".*"}

	ip = os.Args[1]
	community = os.Args[2]
	for i:=0; i<len(os.Args); i++ {
		switch os.Args[i] {
		case "-i":
			interval, err = strconv.Atoi(os.Args[i+1])
			if err != nil {
				log.Fatal(err)
			}
		case "-p":
			patterns = strings.FieldsFunc(os.Args[i+1], func (c rune) bool {
				return c == ','
			})
		}

	}	

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

	interfaces, err := getInterfaces(target, patterns)
	if err != nil {
		log.Fatal(err)
	}
	
	traffics := map[string]*Traffic{}
	for ifIndex := range interfaces {
		traffics[ifIndex] = &Traffic{}
	}

	for {
		inOctets, err := target.BulkWalkAll(oids["ifHCInOctets"])
		if err != nil {
			log.Fatal(err)
		}

		sortedIfIndexs := []string{}
		
		for i:=0; i<len(inOctets); i++ {
			// .1.3.6.1.2.1.31.1.1.1.6.<ifindex>
			// <--- 24 characters ---->
			ifIndex := inOctets[i].Name[24:]
			if _, keyExists := interfaces[ifIndex]; keyExists {
				traffics[ifIndex].In = (inOctets[i].Value.(uint64) - interfaces[ifIndex].ifHCInOctets) * 8
				interfaces[ifIndex].ifHCInOctets = inOctets[i].Value.(uint64)
				sortedIfIndexs = append(sortedIfIndexs, ifIndex)
			}
		}

		outOctets, err := target.BulkWalkAll(oids["ifHCOutOctets"])
		if err != nil {
			log.Fatal(err)
		}

		for i:=0; i<len(outOctets); i++ {
			// .1.3.6.1.2.1.31.1.1.1.10.<ifindex>
			// <---- 25 characters ---->
			ifIndex := outOctets[i].Name[25:]
			if _, keyExists := interfaces[ifIndex]; keyExists {
				traffics[ifIndex].Out = (outOctets[i].Value.(uint64) - interfaces[ifIndex].ifHCOutOctets) * 8
				interfaces[ifIndex].ifHCOutOctets = outOctets[i].Value.(uint64)
			}
		}

		sort.Slice(sortedIfIndexs, func(i, j int) bool {
			left, _ := strconv.Atoi(sortedIfIndexs[i])
			right, _ := strconv.Atoi(sortedIfIndexs[j])
			return left < right
		})

		clearScreen()
		fmt.Println("Interface \t In(bps)   \t Out(bps)")

		for i:=0; i<len(sortedIfIndexs); i++ {
			ifIndex := sortedIfIndexs[i]
			fmt.Printf(
				"%-10v\t %10d\t %10d\n", 
				interfaces[ifIndex].ifName, 
				traffics[ifIndex].In, 
				traffics[ifIndex].Out)
		}

		time.Sleep(time.Duration(interval) * time.Second)

	}
}


func getInterfaces(target *snmp.GoSNMP, patterns []string) (map[string]*ifXEntry, error) {
	// patterns should be able to compile
	var compiledPatterns []*regexp.Regexp
	for i:=0; i<len(patterns); i++ {
		compiledPatterns = append(compiledPatterns, regexp.MustCompile(patterns[i]))
	}

	interfaces := map[string]*ifXEntry{}
	
	results, err := target.BulkWalkAll(oids["ifName"])
	
	for _, pdu := range results {
		// .1.3.6.1.2.1.31.1.1.1.1.<ifindex>
		// <--- 24 characters ---->
		ifName := string(pdu.Value.([]uint8))
		for i:=0; i<len(compiledPatterns); i++ {
			if compiledPatterns[i].MatchString(ifName) {
				interfaces[pdu.Name[24:]] = &ifXEntry{ ifName: ifName }
				break
			}
		}
	}

	return interfaces, err
}

func clearScreen() error {
	var clearCmd *exec.Cmd

	if runtime.GOOS == "windows" {
		clearCmd = exec.Command("cls")
	} else if runtime.GOOS == "linux" {
		clearCmd = exec.Command("clear")
	} else if runtime.GOOS == "darwin" {
		clearCmd = exec.Command("clear")
	} else {
		return cantDetectOSTypeError()
	}
	clearCmd.Stdout = os.Stdout
	clearCmd.Run()
	return nil
}

func cantDetectOSTypeError() error {
	return errors.New("can't detect OS type")
}