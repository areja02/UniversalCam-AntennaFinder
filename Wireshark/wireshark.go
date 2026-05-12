package wireshark

import (
	"bufio"
	"fmt"
	customstruct "gopackettrial/CustomStruct"
	"os"
	"strings"
)

func ParseWiresharkOUIFile(file *string, parsedStruct []customstruct.CustomStruct) []customstruct.CustomStruct {
	var newList []customstruct.CustomStruct
	acceptedManufactuers := []string{"AXIS COMMUNICATION", "BOSCH SECURITY", "MIMOSA", "I3 INTERNATIONAL", "HIKVISION", "I-PRO CO", "PANASONIC", "VCS VIDEO", "SIKLU", "UBIQUITI"}
	manufFile := &file
	parsedFile, err := os.Open(**manufFile)
	if err != nil {
		fmt.Println(err)
	}

	fileReader := bufio.NewScanner(parsedFile)
	for fileReader.Scan() {

		lineEntry := fileReader.Text()
		if strings.HasPrefix(lineEntry, "#") || lineEntry == "" {
			continue
		}
		manufParts := strings.Fields(lineEntry)
		if len(manufParts) >= 2 {
			Oui := manufParts[0]
			ShortName := manufParts[1]
			LongName := ""
			specificManufacturer := false
			if len(manufParts) > 2 {
				LongName = strings.Join(manufParts[2:], " ")
			}
			for _, value := range acceptedManufactuers {
				if strings.Contains(strings.ToUpper(LongName), value) {

					specificManufacturer = true
				}
			}
			if specificManufacturer {
				newList = append(newList, customstruct.CustomStruct{
					Oui: Oui, ManShortName: ShortName, ManLongName: LongName})
			}
		}
	}
	return newList
}
