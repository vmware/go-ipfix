// +build ignore

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

func initIANARegistry() {
	registryURL := "https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv"
	data, error := readCSVFromURL(registryURL)
	if error != nil {
		log.Fatalf("main: %v", error)
	}

	registryFileName := "registry_IANA.go"
	var output *os.File
	if output, error = os.Create(registryFileName); error != nil {
		log.Fatalf("main: Cannot open output file %s", registryFileName)
	}
	writer := bufio.NewWriter(output)
	fmt.Fprintf(writer,
		`package registry

import (
	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

// AUTO GENERATED, DO NOT CHANGE

func (registry *ianaRegistry) LoadRegistry() {
`)

	for idx, row := range data {
		// skip header and reserved line
		if idx == 0 || idx == 1 {
			continue
		}

		writer.WriteString("	registry.registerInfoElement(*entities.NewInfoElement(")
		parameters := generateIEString(row[1], row[0], row[2], "0")
		fmt.Fprintf(writer, parameters)
		writer.WriteString("))\n")
	}
	writer.WriteString("}\n")
	writer.Flush()
	output.Close()
}

func initAntreaRegistry() {
	fileName := "registry_antrea.csv"
	data, error := readCSVFromFile(fileName)
	if error != nil {
		log.Fatal(error)
	}
	registryFileName := "registry_antrea.go"
	var output *os.File
	if output, error = os.Create(registryFileName); error != nil {
		log.Fatalf("main: Cannot open output file %s", registryFileName)
	}
	writer := bufio.NewWriter(output)
	fmt.Fprintf(writer,
		`package registry

import (
	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

// AUTO GENERATED, DO NOT CHANGE

func (registry *antreaRegistry) LoadRegistry() {
`)

	for idx, row := range data {
		// skip header
		if idx == 0 {
			continue
		}

		writer.WriteString("	registry.registerInfoElement(*entities.NewInfoElement(")
		parameters := generateIEString(row[1], row[0], row[2], row[12])
		fmt.Fprintf(writer, parameters)
		writer.WriteString("))\n")
	}
	writer.WriteString("}\n")
	writer.Flush()
	output.Close()
}

func readCSVFromURL(url string) ([][]string, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	reader := csv.NewReader(response.Body)
	data, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readCSVFromFile(name string) ([][]string, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func generateIEString(name string, elementid string, datatype string, enterpriseid string) string {
	elementID, _ := strconv.ParseUint(elementid, 10, 16)
	enterpriseID, _ := strconv.ParseUint(enterpriseid, 10, 16)
	dataType := entities.IENameToType(datatype)
	length := uint16(0)
	if entities.IsValidDataType(dataType) {
		length = entities.InfoElementLength[dataType]
	}
	return fmt.Sprintf("\"%s\", %d, %v, %d, %d", name, uint16(elementID), dataType, uint16(enterpriseID), length)
}

func main() {
	switch len(os.Args) {
	case 1:
		initIANARegistry()
		initAntreaRegistry()
	case 2:
		switch strings.ToLower(os.Args[1]) {
		case "antrea":
			initAntreaRegistry()
		case "iana":
			initIANARegistry()
		default:
			log.Fatalln("main: Invalid registry name. Options: \"Antrea\", \"IANA\"")
		}
	default:
		log.Fatalln("main: Invalid number of parameters.")
	}
}
