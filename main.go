package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	customstruct "gopackettrial/CustomStruct"
	wireshark "gopackettrial/Wireshark"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var dbPath = "CameraManufacturers.db"
var manufacturerStruct = customstruct.ManList()

const wiresharkURL string = "https://www.wireshark.org/download/automated/data/manuf"
const internetConnURL string = "https://www.wireshark.org"

var manufFilePTR string = "manuf"
var manufFile *string = &manufFilePTR
var manuString *string

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

func userInput() string {
	reader := bufio.NewReader(os.Stdin)
	usersInput, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Please Insert A Valid Input")
	}
	usersInput = strings.ToUpper(strings.TrimSpace(usersInput))
	return usersInput
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

func main() {
	//Go Routine that makes the application wait for CTRL+C for termination
	gracefulShutdown, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		for {
			select {
			case <-gracefulShutdown.Done():
				return
			default:
				//Beginning of Main Program
				//Asking DB update
				fmt.Println("Would you like to download the latest database and scan? Y or N")
				switch {
				//If yes will update database then proceed onto the default
				case strings.Contains(userInput(), "Y"):
					//Confirming Internet Connection before trying to download
					if checkInternetConn() == true {

						fmt.Println("Confirmed Internet Connection")
						wireSharkFileDownload := downloadWireSharkOUIFile()
						fmt.Println("Downloading Manuf File...")
						if wireSharkFileDownload != nil {
							fmt.Println("Manuf File in Use")
						}

						//Parses the Manuf file through the database created
						//Allows for some time to pass before starting to attempt to delete
						//The downloaded file and performing the network traffic look up
						manufacturerStruct = wireshark.ParseWiresharkOUIFile(&manufFilePTR, manufacturerStruct)
						fmt.Println("Please Wait Updating Database")
						time.Sleep(30 * time.Second)
						fmt.Println("Update Complete")
						fmt.Println("Removing Manuf File, Please Wait...")

						if err := downloadedFileRemovalRetry("manuf"); err != nil {
							log.Printf("Failed to remove Manuf File after retries, %v", err)
						} else {
							fmt.Println("Manuf File Removed successfully...")
						}

						goto nextStep

					} else {
						fmt.Println("No Internet Found...")
						fmt.Println("Proceeding to use local DB...")
						goto nextStep
					}
				nextStep:
					fallthrough
				//If anything else, will just default to the primary scanning
				default:
					fmt.Println("Scanning... Press CTRL + C to exit")
					// Open the device for capturing
					handle, err := pcap.OpenLive(retrieveAdapterName(), 1600, true, pcap.BlockForever)
					if err != nil {
						log.Fatal(err)
					}
					defer handle.Close()

					//Packet Filter
					var filter string = ""
					err = handle.SetBPFFilter(filter)
					if err != nil {
						log.Fatal(err)
					}

					// Use the handle as a packet source to process all packets
					var macAddress string
					var ipAddress string
					packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
					for packet := range packetSource.Packets() {
						//Assigning MacAddress and IPAddress variables values and checking to see if OUI
						//Match is present before printing the information
						macAddress = layer2Packets(packet)
						ipAddress = ipv4Packets(packet)

						//Confirming if received packet are part of the Manufacturer List we want to see
						//If true it prints out the details for us, if false it's ignored.
						if checkOUI(macAddress) {
							fmt.Printf("IP: %s | MAC: %s | %v\n", ipAddress, macAddress, *manuString)
						}
					}

				}
			}
		}
	}()
	//Termination Signal Recieved, exiting Program
	<-gracefulShutdown.Done()
	cancel()
	fmt.Printf("\nTermination Received...\n")
	fmt.Println("Exiting Program...")
}
