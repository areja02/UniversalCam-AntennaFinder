package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	database "fyneapp/Database"
	wireshark "fyneapp/WiresharkParsing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func checkInternetConn() bool {
	//Reaches out to the wireshark website to check if there is internet
	//Depending if it fails or recieves a reponse, it'll confirm the connection
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(internetConnURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent
}

func retrieveAdapterName() string {
	//Goes through our adapaters and finds which one is a realtek or intel
	//Ethernet adapter and sets that to our network interface
	var ethernet string
	adapters, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	for _, adapterName := range adapters {
		if strings.Contains(adapterName.Description, "Realtek") || strings.Contains(adapterName.Description, "Intel") && strings.Contains(adapterName.Description, "Ethernet") {
			ethernet = adapterName.Name
		}
	}
	return ethernet
}
func layer2Packets(packet gopacket.Packet) string {
	//Returns our MAC Address from the packet recieved
	var macString string
	layer2Packet := packet.Layer(layers.LayerTypeEthernet)
	if layer2Packet != nil {
		layer2, _ := layer2Packet.(*layers.Ethernet)
		macString = fmt.Sprintf("%v", layer2.SrcMAC)
		macString = strings.ToUpper(macString)
		macString = strings.TrimSpace(macString)
	}
	return macString
}

func ipv4Packets(packet gopacket.Packet) string {
	//Returns our IP Address from the packet recieved
	var ipString string
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipString = fmt.Sprintf("%v\n", ip.SrcIP)
		ipString = strings.TrimSpace(ipString)
	}
	return ipString
}

func downloadWireSharkOUIFile() error {
	//Function that will download the Manuf file needed to update our
	//Manufacturer Database (Custom Struct)
	wiresharkGetRequest, err := http.Get(wiresharkURL)
	if err != nil {
		log.Panic(err)
	}
	defer wiresharkGetRequest.Body.Close()

	createdTXTFile, err := os.Create("manuf")
	if err != nil {
		return err
	}
	defer createdTXTFile.Close()

	_, err = io.Copy(createdTXTFile, wiresharkGetRequest.Body)
	return err

}
func downloadedFileRemovalRetry(file string) error {
	//A function that will remove the downloaded Manuf File
	err := os.Remove(file)
	if err == nil {
		return nil
	}
	maxTries := 20
	for i := 0; i < maxTries; i++ {
		time.Sleep(10 * time.Second)
		err = os.Remove(file)
		if err == nil {
			return nil
		}
	}
	return err
}
func checkOUI(mac string) bool {
	//Checks to see if the Mac Address of the packet received
	//Is part of one of the manufacturer OUIs in our database
	for _, value := range manufacturerStruct {
		value.Oui = strings.TrimSpace(value.Oui)
		if strings.Contains(mac, value.Oui) {
			manuString = &value.ManLongName
			return true
		}
	}
	return false
}

var manufacturerStruct = database.ManList()
var scanButton *widget.Button
var updateDatabaseButton *widget.Button
var clearScreenButton *widget.Button
var manufFilePTR string = "manuf"
var manufFile *string = &manufFilePTR
var manuString *string
var currentlyScanning bool
var quitGoRoutine = make(chan struct{})
var lines []string

const wiresharkURL string = "https://www.wireshark.org/download/automated/data/manuf"
const internetConnURL string = "https://www.wireshark.org"
const maxbufferSize = 20

func main() {
	a := app.New()
	myWindow := a.NewWindow("Device Discovery Application")
	textConsole := widget.NewTextGrid()
	scrollPane := container.NewScroll(textConsole)

	//Button Used To Clear The Data
	clearScreenButton = widget.NewButton("Clear Screen", func() {
		fyne.Do(func() { textConsole.SetText(" ") })
	})

	//Button Used To Update The Local Database
	updateDatabaseButton = widget.NewButton("Update Database", func() {
		//Disabling All Buttons till either error out or update is complete
		updateDatabaseButton.Disable()
		scanButton.Disable()
		clearScreenButton.Disable()

		go func() {
			//Enabling Buttons Upon Completion / Error
			defer fyne.Do(func() {
				updateDatabaseButton.Enable()
				scanButton.Enable()
				clearScreenButton.Enable()
			})
			/*
				Checks if there is internet connection. Will notify if there isn't any to update the database.
				If there is internet, will download the latest Manuf file from wireshark's
				website then parses the file to only retrieve the manufacturers specified in
				the wireshark package. Once parsing is complete, application will remove
				the downloaded Manuf File and unlock the application.
			*/
			if !checkInternetConn() {
				fyne.Do(func() {
					textConsole.SetText("No Internet connection \n Utilizing local Database..")
					return
				})
			}
			if checkInternetConn() == true {
				fyne.Do(func() {
					textConsole.SetText("Downloading Manuf File..")
				})
				wiresharkDownload := downloadWireSharkOUIFile()

				if wiresharkDownload != nil {
					fyne.Do(func() { textConsole.SetText("Manuf File Currently In Use...") })
				}
				fyne.Do(func() {
					textConsole.SetText("Please Wait..")
				})
				manufacturerStruct = wireshark.ParseWiresharkOUIFile(&manufFilePTR, manufacturerStruct)
				fyne.Do(func() {
					textConsole.SetText("Updating Database..")
				})
				time.Sleep(30 * time.Second)
				fyne.Do(func() {
					textConsole.SetText("Update Complete.. Removing Manuf File..")
				})
				if err := downloadedFileRemovalRetry("manuf"); err != nil {
					fyne.Do(func() {
						textConsole.SetText("Failed to remove Manuf File after retries")
					})
				} else {
					fyne.Do(func() {
						textConsole.SetText("Manuf File Removed Successfully... \nDatabase Update has Completed. Please begin scanning.")
					})
				}
			}
		}()
	})

	//Button Used For Scanning For Devices.
	scanButton = widget.NewButton("Start Scan", func() {
		updateDatabaseButton.Disable()
		if !currentlyScanning {
			quitGoRoutine = make(chan struct{})
			currentlyScanning = true
			scanButton.SetText("Stop")
			go func() {
				defer fyne.Do(func() {
					updateDatabaseButton.Enable()
				})

				handle, err := pcap.OpenLive(retrieveAdapterName(), 1600, true, pcap.BlockForever)
				if err != nil {
					panic(err)
				}
				defer handle.Close()
				err = handle.SetBPFFilter("")
				if err != nil { // optional
					panic(err)
				}

				packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packetSource.Packets() {
					select {
					case <-quitGoRoutine:
						return
					default:
						fyne.Do(func() {
							var newLog string
							macAddress := layer2Packets(packet)
							ipAddress := ipv4Packets(packet)
							if checkOUI(macAddress) {
								if ipAddress == "" {
									return
								} else {
									newLog = fmt.Sprintf("IP: %v | MAC: %v | %v\n", ipAddress, macAddress, *manuString)
									lines = strings.Split(textConsole.Text(), "\n")

									lines = append(lines, newLog)
									if len(lines) > maxbufferSize {
										lines = lines[len(lines)-maxbufferSize:]
									}
									textConsole.SetText(strings.Join(lines, "\n"))
									scrollPane.ScrollToBottom()
									time.Sleep(20 * time.Millisecond)

								}
							}
						})
					}
				}
			}()
		} else {
			close(quitGoRoutine)
			currentlyScanning = false
			scanButton.SetText("Start Scanning")
		}

	})

	mainWindow := container.NewBorder(container.NewVBox(container.NewGridWithColumns(3, scanButton, updateDatabaseButton, clearScreenButton)), nil, nil, nil, scrollPane)
	myWindow.SetContent(mainWindow)
	myWindow.Resize(fyne.NewSize(500, 300))
	myWindow.ShowAndRun()

}
