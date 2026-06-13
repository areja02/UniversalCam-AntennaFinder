package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
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
var manufacturerListSelection = []string{"AXIS COMMUNICATION", "BOSCH SECURITY", "MIMOSA", "I3 INTERNATIONAL", "HIKVISION", "I-PRO CO", "HANWHA", "PANASONIC", "VCS VIDEO", "SIKLU", "UBIQUITI"}

const wiresharkURL string = "https://www.wireshark.org/download/automated/data/manuf"
const internetConnURL string = "https://www.wireshark.org"
const maxbufferSize = 20

func main() {
	a := app.New()
	myWindow := a.NewWindow("Device Discovery Application")
	screenListings := widget.NewList(
		func() int {
			return len(lines)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(lines[id])
		},
	)

	//Button Used To Clear The Data
	clearScreenButton = widget.NewButton("Clear Screen", func() {
		fyne.Do(func() {
			lines = []string{}
			screenListings.Refresh()
		})
	})

	/*
		Checkbox selections on the manufacturers you want to see.
		Created an all checkbox, which is enabled by default. Can uncheck and select the specific ones you wish to see.
	*/
	manufacturerCheckBoxSelection := widget.NewCheckGroup(manufacturerListSelection, func(selected []string) {
	})
	checkAllManufacturerSelection := widget.NewCheck("All", func(checked bool) {
		if checked {
			manufacturerCheckBoxSelection.SetSelected(manufacturerListSelection)
		} else {
			manufacturerCheckBoxSelection.SetSelected([]string{})
		}
	})
	checkAllManufacturerSelection.SetChecked(true)

	//Button Used To Update The Local Database
	updateDatabaseButton = widget.NewButton("Update Database", func() {
		//Disabling All Buttons till either error out or update is complete
		updateDatabaseButton.Disable()
		scanButton.Disable()
		clearScreenButton.Disable()
		checkAllManufacturerSelection.Disable()
		manufacturerCheckBoxSelection.Disable()
		go func() {
			//Enabling Buttons Upon Completion / Error
			defer fyne.Do(func() {
				updateDatabaseButton.Enable()
				scanButton.Enable()
				clearScreenButton.Enable()
				checkAllManufacturerSelection.Enable()
				manufacturerCheckBoxSelection.Enable()
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
					lines = append(lines, "No internet Connection \n Please proceed with scanning..")
					return
				})
			}
			if checkInternetConn() == true {
				fyne.Do(func() {
					lines = []string{}
					screenListings.Refresh()
				})
				fyne.Do(func() {
					lines = append(lines, "Downloading Manuf File..")
					screenListings.Refresh()
				})
				wiresharkDownload := downloadWireSharkOUIFile()

				if wiresharkDownload != nil {
					fyne.Do(func() {
						lines = append(lines, "Manuf File Currently In Use...")
						screenListings.Refresh()
					})
				}
				fyne.Do(func() {
					lines = append(lines, "Please Wait..")
					screenListings.Refresh()
				})
				manufacturerStruct = wireshark.ParseWiresharkOUIFile(&manufFilePTR, manufacturerStruct)
				fyne.Do(func() {
					lines = append(lines, "Updating Database..")
					screenListings.Refresh()
				})
				time.Sleep(30 * time.Second)
				fyne.Do(func() {
					lines = append(lines, "Update Complete.. Removing Manuf File..")
					screenListings.Refresh()
				})
				if err := downloadedFileRemovalRetry("manuf"); err != nil {
					fyne.Do(func() {
						lines = append(lines, "Failed to remove Manuf File after retries")
						screenListings.Refresh()
					})
				} else {
					fyne.Do(func() {
						lines = append(lines, "Manuf File Removed Successfully... \n\nDatabase Update has Completed. Please begin scanning.")
						screenListings.Refresh()
					})
				}
			}
		}()
	})

	//Button Used For Scanning For Devices.
	scanButton = widget.NewButton("Start Scan", func() {
		//Initial lines simply disable certain functions during scanninng, as well as clears
		//The window. Enables the options once scanning stops.
		updateDatabaseButton.Disable()
		checkAllManufacturerSelection.Disable()
		manufacturerCheckBoxSelection.Disable()
		if !currentlyScanning {
			quitGoRoutine = make(chan struct{})
			currentlyScanning = true
			scanButton.SetText("Stop")
			go func() {
				fyne.Do(func() {
					lines = []string{}
					screenListings.Refresh()
				})
				defer fyne.Do(func() {
					updateDatabaseButton.Enable()
					checkAllManufacturerSelection.Enable()
					manufacturerCheckBoxSelection.Enable()
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

				//Ensures at least one checkbox is selected before allowing to scan
				fyne.Do(func() {
					if len(manufacturerCheckBoxSelection.Selected) == 0 {
						currentlyScanning = false
						close(quitGoRoutine)
						scanButton.SetText("Start Scanning")
						lines = append(lines, "Please Select At Least One Manufacturer Before Scanning")
						screenListings.Refresh()
					}
				})

				packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packetSource.Packets() {
					select {
					case <-quitGoRoutine:
						return
					default:
						fyne.Do(func() {
							//Packet Capturing Process
							var newLog string
							macAddress := layer2Packets(packet)
							ipAddress := ipv4Packets(packet)

							if checkOUI(macAddress) {
								if ipAddress == "" {
									return
								} else {
									newLog = fmt.Sprintf("IP: %v | MAC: %v | %v\n", ipAddress, macAddress, *manuString)
									//Evaluating whether the found packets are selected and are not already being shown
									//On the window.
									for _, item := range manufacturerCheckBoxSelection.Selected {
										if strings.Contains(strings.ToUpper(*manuString), item) {
											if !slices.Contains(lines, newLog) {
												lines = append(lines, newLog)
											} else {
												return
											}
											if len(lines) > maxbufferSize {
												lines = lines[len(lines)-maxbufferSize:]
											}
											screenListings.Refresh()
											time.Sleep(20 * time.Millisecond)
										}
									}

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

	mainWindow := container.NewBorder(container.NewVBox(container.NewGridWithColumns(3, scanButton, updateDatabaseButton, clearScreenButton)), nil, container.NewVBox(checkAllManufacturerSelection, manufacturerCheckBoxSelection), nil, screenListings)
	myWindow.SetContent(mainWindow)
	myWindow.Resize(fyne.NewSize(800, 500))
	myWindow.ShowAndRun()

}
