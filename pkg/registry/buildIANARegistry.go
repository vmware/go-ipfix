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

	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

func initIANARegistry() {
	registryUrl := "https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv"
	data, error := readCSVFromUrl(registryUrl)
	if error != nil {
		log.Fatal(error)
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

func LoadIANARegistry() {
`)

	for idx, row := range data {
		// skip header and reserved line
		if idx == 0 || idx == 1 {
			continue
		}

		writer.WriteString("	RegisterInfoElement(*entities.NewInfoElement(")
		name := row[1]
		elementId, _ := strconv.ParseUint(row[0], 10, 16)
		dataType := entities.IENameToType(row[2])
		enterpriseID := 0
		length := uint16(0)
		if entities.IsValidDataType(dataType) {
			length = entities.InfoElementLength[dataType]
		}
		fmt.Fprintf(writer, "\"%s\", %d, %v, %d, %d", name, uint16(elementId), dataType, enterpriseID, length)
		writer.WriteString("))\n")
	}
	writer.WriteString("}\n")
	writer.Flush()
	output.Close()
}

func readCSVFromUrl(url string) ([][] string, error) {
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

func main() {
	initIANARegistry()
}