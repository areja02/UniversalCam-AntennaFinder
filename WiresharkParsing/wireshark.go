package wireshark

import (
	"bufio"
	"fmt"
	database "fyneapp/Database"
	"os"
	"strings"
)

func ParseWiresharkOUIFile(file *string, parsedStruct []database.CustomStruct) []database.CustomStruct {
	var newList []database.CustomStruct
	acceptedManufactuers := []string{"AXIS COMMUNICATION", "BOSCH SECURITY", "MIMOSA", "I3 INTERNATIONAL", "HIKVISION", "I-PRO CO", "PANASONIC", "VCS VIDEO", "SIKLU", "UBIQUITI", "HANWHA"}
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
				newList = append(newList, database.CustomStruct{
					Oui: Oui, ManShortName: ShortName, ManLongName: LongName})
			}
		}
	}
	return newList
}
