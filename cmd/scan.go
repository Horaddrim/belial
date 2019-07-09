/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	belial "github.com/horaddrim/belial/lib"
	"github.com/spf13/cobra"
)

// Flag for how many seconds we should wait until
// provoke a new round of ARP packets to be send
// to the broadcast address.
var interval string

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [interface to scan]",
	Short: "Start listening to ARP packets in the given interface",
	Long: `Start listening to ARP packets in the given interface and print them to the STDOUT.
	Also sends packets to the broadcast address so you can have all the MAC and IP addresses in your local network 
	when the respective hosts answers the ARP request.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) <= 0 {
			return errors.New("[ERROR]: You should specify a interface.")
		}

		if _, err := net.InterfaceByName(args[0]); err != nil {
			return errors.New("[ERROR]: Invalid interface.")
		}

		tryInterval, err := cmd.Flags().GetString("interval")

		if err != nil {
			return errors.New("[ERROR]: Cannot parse interval flag.")
		}

		_, err = time.ParseDuration(tryInterval)

		if err != nil {
			log.Printf("[ERROR]: Cannot parse %s", interval)
			return err
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var validAddress *net.IPNet

		networkInterface, _ := net.InterfaceByName(args[0])

		addresses, err := networkInterface.Addrs()

		if err != nil {
			log.Printf("[ERROR]: %s", err.Error())
			return
		}

		for _, address := range addresses {
			if ipnet, ok := address.(*net.IPNet); ok {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					validAddress = &net.IPNet{
						IP:   ipv4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}

					break
				}
			}
		}

		if validAddress == nil {
			log.Println("[ERROR]: No valid IP network found.")
			return
		}

		if validAddress.IP[0] == 127 {
			log.Println("[ERROR]: Skip scanning loopback interface.")
			return
		}

		if validAddress.Mask[0] != 0xff || validAddress.Mask[1] != 0xff {
			log.Println("[ERROR]: Mask means network is too large.")
			return
		}

		log.Printf("Using network range %v for interface %v", validAddress, networkInterface.Name)

		// Open up a pcap handle for packet reads/writes.
		handle, err := pcap.OpenLive(networkInterface.Name, 65536, true, pcap.BlockForever)

		if err != nil {
			log.Printf("[ERROR]: %s", err.Error())
			return
		}

		defer handle.Close()

		// Start up a goroutine to read in packet data.
		stopChannel := make(chan os.Signal, 1)
		defer close(stopChannel)

		var wg sync.WaitGroup

		// Handles the SIGINT (Ctrl + C) process signal
		// to shutdown gracefully.
		signal.Notify(stopChannel, os.Interrupt)

		wg.Add(2)
		go belial.ReadARP(&wg, handle, networkInterface, stopChannel)
		go belial.WriteARPOnInterval(interval, stopChannel, &wg, handle, networkInterface, validAddress)

		wg.Wait()
		return
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	scanCmd.PersistentFlags().StringVarP(&interval, "interval", "i", "20s", `
		The interval used to ask for ARP packages. 
		A duration string is a possibly signed sequence of decimal numbers,
		each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
		Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".`)

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
