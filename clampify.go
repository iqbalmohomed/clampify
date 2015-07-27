package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
)

const (
	Rehersal    = true
	ShowCommand = true
	ShowOutput  = true
	Debug       = true
)

func print_help() {
	fmt.Println("Help:")
	fmt.Println("Please provide arguments as follows:")
	fmt.Println("create net-name netns -> IP address, Neutron Port ID")
	fmt.Println("delete port-id netns")
	fmt.Println("insert net-name container-id")
	fmt.Println("reinsert container-id port-id ip-address")
	fmt.Println("watch net-name")
	fmt.Println("clear-neutron-ports")
}

type DockerDaemonMessage struct {
	Status, Id, From string
	Time             int64
}

func listenToDockerDaemonMessages(ch chan<- DockerDaemonMessage) {
	conn, err := net.Dial("tcp", "0.0.0.0:2375")
	if err != nil {
		log.Fatal(err)
	}

	clientConn := httputil.NewClientConn(conn, nil)

	req, err := http.NewRequest("GET", "/events", nil)
	if err != nil {
		log.Fatal(err)
	}

	resp, err := clientConn.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	dec := json.NewDecoder(resp.Body)

	for {
		var m DockerDaemonMessage
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s\n", m.Status, m.Id)
		ch <- m
	}
}

type Config struct {
	HostName, HostIPAddress, NetSize, BroadcastIPAddress, NeutronServerIPAddress, InspectAtStartup string
}

type ContainerNetworkInfo struct {
	ContainerID        string
	NetworkNamespace   string
	NeutronPortID      string
	MacAddress         string
	IPAddress          string
	NeutronNetworkName string
}

func processConfigFile() *Config {
	data, err := ioutil.ReadFile("clampify.conf")
	if err != nil {
		log.Println("Error reading config file")
		log.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")

	//var m map[string] string
	m := make(map[string]string)

	for _, line := range lines {
		if strings.Contains(line, "=") {
			toks := strings.Split(line, "=")
			m[toks[0]] = toks[1]
		}
	}
	config := new(Config)
	config.HostName = m["host-name"]
	config.HostIPAddress = m["host-ipaddress"]
	config.NetSize = m["net-size"]
	config.BroadcastIPAddress = m["broadcast-ipaddress"]
	config.NeutronServerIPAddress = m["neutronserver-ipaddress"]
	config.InspectAtStartup = m["inspect-at-startup"]
	return config
}

// Main entry point. Clampify agent can be run as a CLI tool or as a Daemon with the watch option
func main() {
	config := processConfigFile()
	fmt.Println("Network Attach Utility Started on " + config.HostName)
	if config.InspectAtStartup == "yes" {
		fmt.Println("Inspecting state of Neutron at startup")
		mapped_ports := inspect_existing_neutron_ports(config.HostName)
		fmt.Println("Found ", len(mapped_ports), " ports on this host")
	}
	//runSudo("ovs-vsctl show", true, true, true)
	//createVIF("192.168.1.5/24","192.168.1.255","a54be265-98f8-4275-bdeb-3d3d73221d10","fa:16:3e:b4:8a:d5","purple")
	//txt := runCmdWithOutput("source ~/openrc;keystone token-get",true,true,false,true)
	//a_map := makeMapFromOutput(txt)
	//fmt.Println(get_auth_token_id())

	if len(os.Args) > 1 {
		if os.Args[1] == "create" {
			netname := os.Args[2]
			netns := os.Args[3]
			port_id, mac_address, ip_address := make_neutron_port(netname)
			createVIF(ip_address+config.NetSize, config.BroadcastIPAddress, port_id, mac_address, netns)
			associate_port_with_host(port_id, config.HostName, config.NeutronServerIPAddress)
			fmt.Printf("IP_ADDRESS: %s, PORT_ID: %s\n", ip_address, port_id)
		} else if os.Args[1] == "delete" {
			port_id := os.Args[2]
			netns := os.Args[3]
			delete_neutron_port(port_id)
			deleteVIF(port_id, netns)
		} else if os.Args[1] == "clear-neutron-ports" {
			delete_all_neutron_ports_on_host(config.HostName)
		} else if os.Args[1] == "watch" {
			containerInfo := make(map[string]*ContainerNetworkInfo)
			netname := os.Args[2]
			messages := make(chan DockerDaemonMessage)
			go listenToDockerDaemonMessages(messages)
			var m DockerDaemonMessage
			for {
				m = <-messages
				fmt.Printf("%s: %s\n", m.Status, m.Id)
				container_id := m.Id
				if m.Status == "start" {
					containerInfo[container_id] = init_nw(netname, container_id, config.HostName, config.NeutronServerIPAddress, config.BroadcastIPAddress, config.NetSize)
					if Debug {
						for c := range containerInfo {
							fmt.Printf("%+v\n", *containerInfo[c])
						}
					}
				} else if m.Status == "destroy" {
					if containerRef, ok := containerInfo[container_id]; ok {
						delete_nw(containerRef)
					} else if Debug {
						fmt.Println("Container with no metadata was destroyed. Manual cleanup may be needed")
					}

				}
			}
		} else if os.Args[1] == "insert" {
			netname := os.Args[2]
			container_id := os.Args[3]
			port_id, mac_address, ip_address := make_neutron_port(netname)
			createVIFOnHost(port_id, mac_address)
			portName := port_id[:11]
			netns := container_id
			createNSForDockerContainer(container_id)
			addTapDeviceToNetNS(portName, netns)
			applyIPAddressToTapDeviceInNetNS(ip_address+config.NetSize, config.BroadcastIPAddress, portName, netns)
			associate_port_with_host(port_id, config.HostName, config.NeutronServerIPAddress)

		} else if os.Args[1] == "reinsert" {
			container_id := os.Args[2]
			port_id := os.Args[3]
			ip_address := os.Args[4]
			portName := port_id[:11]
			netns := container_id
			createNSForDockerContainer(container_id)
			addTapDeviceToNetNS(portName, netns)
			applyIPAddressToTapDeviceInNetNS(ip_address+config.NetSize, config.BroadcastIPAddress, portName, netns)
			associate_port_with_host(port_id, config.HostName, config.NeutronServerIPAddress)

		} else {
			print_help()
		}
	} else {
		print_help()
	}

	/*
		// Uncomment to create a Neutron port
		var netname string
		netname = "demo-net"
		port_id,mac_address,ip_address := make_neutron_port(netname)
		fmt.Printf("port id: %s, mac address: %s,ip address: %s\n", port_id,mac_address, ip_address)

		// Uncomment to delete a neutron port
		//delete_neutron_port("23f0d8da-b9bf-4479-957c-a0c59c6a4ac0")

		// Uncomment to create VIF and plug it in
		//createVIF("192.168.1.5/24","192.168.1.255","a54be265-98f8-4275-bdeb-3d3d73221d10","fa:16:3e:b4:8a:d5","purple")
		createVIF( ip_address+ "/24","192.168.1.255",port_id,mac_address,"yellow")
		//delete_neutron_port(port_id)
	*/

	// Uncomment to associate a port with a specific compute node:
	//associate_port_with_host("c351be95-6578-4154-88f2-0cfc17fecaf4","vizio-devswarm-host1","10.120.39.40")

	// Uncomment to delete Neutron port
	//delete_neutron_port("b58f6d35-89b8-467b-abc7-3faea4e4df24")

	// Uncomment to delete the VIF
	//deleteVIF("b58f6d35-89b8-467b-abc7-3faea4e4df24","yellow")
}

func delete_nw(c_info *ContainerNetworkInfo) {
	delete_neutron_port(c_info.NeutronPortID)
	deleteVIF(c_info.NeutronPortID, c_info.NetworkNamespace)
}

func associate_port_with_host(port_id, compute_node_name, neutron_server_ipaddress string) {
	/*
		curl -g -i --cacert "/opt/stack/data/CA/int-ca/ca-chain.pem" -X PUT http://10.0.2.15:9696/v2.0/ports/a54be265-98f8-4275-bdeb-3d3d73221d10.json -H "User-Agent: python-neutronclient" -H "Accept: application/json" -H "X-Auth-Token: ed09a406b71248b1b167f638f8897f72" -d '{"port":{"binding:host_id": "vagrant-ubuntu-trusty-64.localdomain"}}'
		curl -g -i --cacert "/opt/stack/data/CA/int-ca/ca-chain.pem" -X PUT http://10.0.2.15:9696/v2.0/ports/a54be265-98f8-4275-bdeb-3d3d73221d10.json -H "User-Agent: python-neutronclient" -H "Accept: application/json" -H "X-Auth-Token: ed09a406b71248b1b167f638f8897f72" -d '{"port":{"device_id": "vagrant-ubuntu-trusty-64.localdomain"}}'
	*/
	auth_token := get_auth_token_id()
	var cmdToRun string
	cmdToRun = fmt.Sprintf(`curl -g -i -X PUT http://%s:9696/v2.0/ports/%s.json -H "User-Agent: python-neutronclient" -H "Accept: application/json" -H "X-Auth-Token: %s" -d '{"port":{"binding:host_id": "%s"}}'`, neutron_server_ipaddress, port_id, auth_token, compute_node_name)
	runCmd(cmdToRun, false, true, false)
	cmdToRun = fmt.Sprintf(`curl -g -i -X PUT http://%s:9696/v2.0/ports/%s.json -H "User-Agent: python-neutronclient" -H "Accept: application/json" -H "X-Auth-Token: %s" -d '{"port":{"device_id": "%s"}}'`, neutron_server_ipaddress, port_id, auth_token, compute_node_name)
	runCmd(cmdToRun, false, true, false)
}

func init_nw(netname string, container_id string, compute_node_name string, neutron_server_ipaddress string, broadcastAddress string, net_size string) *ContainerNetworkInfo {
	port_id, mac_address, ip_address := make_neutron_port(netname)
	createVIFOnHost(port_id, mac_address)
	portName := port_id[:11]
	netns := container_id
	createNSForDockerContainer(container_id)
	addTapDeviceToNetNS(portName, netns)
	applyIPAddressToTapDeviceInNetNS(ip_address+net_size, broadcastAddress, portName, netns)
	associate_port_with_host(port_id, compute_node_name, neutron_server_ipaddress)
	res := &ContainerNetworkInfo{container_id, netns, port_id, mac_address, ip_address, netname}
	return res
}

func delete_all_neutron_ports_on_host(hostname string) {
	fmt.Println("Inspecting state of Neutron")
	mapped_ports_on_host := inspect_existing_neutron_ports(hostname)
	fmt.Println("Found", len(mapped_ports_on_host), "ports on this host")
	for _, map_val := range mapped_ports_on_host {
		fmt.Println("Deleting port", map_val["id"])
		delete_neutron_port(map_val["id"])
	}
}

// Given a Neutron port-id, delete the port
func delete_neutron_port(port_id string) {
	cmdToRun := fmt.Sprintf("source ~/openrc;neutron port-delete %s", port_id)
	runCmdWithOutput(cmdToRun, false, false, false, false)
}

// Given an existing Neutron network name, create a port and return the port id, mac address and ip address
// Returns port_id, mac address and ip address
func make_neutron_port(networkName string) (string, string, string) {
	cmdToRun := fmt.Sprintf("source ~/openrc;neutron port-create %s", networkName)
	txt := runCmdWithOutput(cmdToRun, false, true, false, true)
	a_map := makeMapFromOutput(txt)
	fixed_ips := a_map["fixed_ips"]
	fmt.Println(fixed_ips)
	var ip_address string
	type ip_info struct {
		Subnet_id  string `json:"subnet_id"`
		Ip_address string `json:"ip_address"`
	}
	dec := json.NewDecoder(strings.NewReader(fixed_ips))
	var m ip_info
	err := dec.Decode(&m)
	if err == nil {
		ip_address = m.Ip_address
	} else {
		ip_address = ""
		fmt.Println("Error", err)
	}
	return a_map["id"], a_map["mac_address"], ip_address
}

// Inspect all existing Neutron ports
func inspect_existing_neutron_ports(hostname string) []map[string]string {
	cmdToRun := fmt.Sprintf("source ~/openrc;neutron port-list -c id -c mac_address -c binding:host_id -c fixed_ips")
	txt := runCmdWithOutput(cmdToRun, false, true, false, true)
	cmdResults := make_maps_from_lines(txt, false)
	result := []map[string]string{}
	for _, map_val := range cmdResults {
		if map_val["binding:host_id"] == hostname {
			result = append(result, map_val)
		}
	}
	return result
}

// This function helps to deal with the output of the Openstack CLIs. Particularly, for functions that return a header row followed by content, this function will be useful.
// Expected input format:
// -----------------------------
// | TOK_HEADER1 | TOK_HEADER2 |
// -----------------------------
// | LINE1_V1    | LINE1_V2    |
// | LINE2_V1    | LINE2_V2    |
// -----------------------------
// Output: Slice of maps, where each map corresponds to a line of values. The above sample input would result in a slice of two maps. The first map would be
// {TOK_HEADER1: LINE1_V1 , TOK_HEADER2: LINE1_V2}
// Each of the values are trimmed and assumed to be string values
func make_maps_from_lines(txt []byte, verbose bool) []map[string]string {
	lines := strings.Split(string(txt), "\n")
	result := []map[string]string{}
	if len(lines) > 4 {
		keys := []string{}
		toks := strings.Split(lines[1], "|")
		for _, tok := range toks {
			trimmed_tok := strings.TrimSpace(tok)
			if trimmed_tok != "" {
				if verbose {
					fmt.Println("Token", tok)
				}
			}
			// Add blank tokens to the token slice. We will filter them out of the map later
			keys = append(keys, strings.TrimSpace(tok))
		}
		// Process rows with values
		content_lines := lines[3 : len(lines)-2]
		for _, line := range content_lines {
			//fmt.Println(idx, line)
			map_for_line := map[string]string{}
			line_toks := strings.Split(line, "|")
			for line_item_idx, line_item := range line_toks {
				trimmed_tok := strings.TrimSpace(line_item)
				if keys[line_item_idx] != "" {
					map_for_line[keys[line_item_idx]] = trimmed_tok
				}
			}
			result = append(result, map_for_line)
			if verbose {
				fmt.Printf("%+v\n", map_for_line)
			}
		}
	}
	return result
}

func get_auth_token_id() string {
	txt := runCmdWithOutput("source ~/openrc;keystone token-get", false, true, false, true)
	a_map := makeMapFromOutput(txt)
	return a_map["id"]
}

func makeMapFromOutput(txt []byte) map[string]string {
	m := map[string]string{}
	n := len(txt)
	s := string(txt[:n])
	res := strings.Split(s, "\n")
	for _, e := range res {
		if strings.HasPrefix(e, "|") {
			toks := strings.Split(e, "|")
			key := strings.TrimSpace(toks[1])
			val := strings.TrimSpace(toks[2])
			m[key] = val
		}
	}
	return m
}

func runSudo(cmd string, showOutput bool, showCommand bool, rehersal bool) {
	runCmd("sudo "+cmd, showOutput, showCommand, rehersal)
}

func runSudoWithOutput(cmd string, showOutput bool, showCommand bool, rehersal bool) []byte {
	return runCmdWithOutput("sudo "+cmd, showOutput, showCommand, rehersal, true)
}

func runCmdWithOutput(cmdString string, showOutput bool, showCommand bool, rehersal bool, returnOutput bool) []byte {
	if showCommand == true {
		fmt.Printf("Cmd: %s\n", cmdString)
	}

	if rehersal == false {
		cmd := exec.Command("/bin/sh", "-c", cmdString)

		out, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		if showOutput == true {
			fmt.Printf("Result: %s\n", out)
		}
		if returnOutput == true {
			return out
		}
	}
	return nil
}

func runCmd(cmdString string, showOutput bool, showCommand bool, rehersal bool) {
	if showCommand == true {
		fmt.Printf("Cmd: %s\n", cmdString)
	}

	if rehersal == false {
		cmd := exec.Command("/bin/sh", "-c", cmdString)

		out, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		if showOutput == true {
			fmt.Printf("Result: %s\n", out)
		}
	}
}

func attachTapDeviceToOVSBridge(portName string, portid string, macaddress string, bridge string) {
	cmdToRun := fmt.Sprintf("ovs-vsctl -- --if-exists del-port %[1]s -- add-port %[4]s %[1]s -- set Interface %[1]s  type=internal -- set Interface %[1]s  external-ids:iface-id=%[2]s -- set  Interface %[1]s external-ids:iface-status=active -- set Interface %[1]s external-ids:attached-mac='%[3]s'", portName, portid, macaddress, bridge)
	runSudo(cmdToRun, true, true, false)
}

func setTapDeviceMacAddress(portName string, macaddress string) {
	cmdToRun := fmt.Sprintf("ip  link  set  %[1]s  address  %[2]s", portName, macaddress)
	runSudo(cmdToRun, true, true, false)
}

func initNetNS(netns string) {
	var cmdToRun string
	// Create the network namespace
	cmdToRun = fmt.Sprintf("ip  netns  add  %s", netns)
	runSudo(cmdToRun, true, true, false)

	// Setup the secondary interfaces for automatic promotion
	cmdToRun = fmt.Sprintf("ip  netns  exec  %s  sysctl  -w  net.ipv4.conf.all.promote_secondaries=1", netns)
	runSudo(cmdToRun, true, true, false)

	// Bring up the loopback interface
	cmdToRun = fmt.Sprintf("ip  netns  exec  %s  ip  link  set  lo  up", netns)
	runSudo(cmdToRun, true, true, false)

}

func deleteOVSPort(portName, bridge string) {
	// Delete the OVS port
	cmdToRun := fmt.Sprintf("ovs-vsctl del-port %s %s", bridge, portName)
	runSudo(cmdToRun, true, true, false)
}

func deleteNetNS(netns string) {
	// Delete the network namespace
	cmdToRun := fmt.Sprintf("ip  netns  delete  %s", netns)
	runSudo(cmdToRun, true, true, false)
}

func addTapDeviceToNetNS(portName string, netns string) {
	var cmdToRun string
	// Move tap device to network namespace
	cmdToRun = fmt.Sprintf("ip  link  set  %s  netns  %s", portName, netns)
	runSudo(cmdToRun, true, true, false)
	// Bring up the tap device
	cmdToRun = fmt.Sprintf("ip  netns  exec  %s  ip  link  set  %s  up", netns, portName)
	runSudo(cmdToRun, true, true, false)
}

func applyIPAddressToTapDeviceInNetNS(ipAddressInCIDR string, broadcastAddress string, portName string, netns string) {
	var cmdToRun string
	// Set up IP address and broadcast address on tap device
	cmdToRun = fmt.Sprintf("ip  netns  exec  %s  ip  -4  addr  add  %s  brd  %s  scope  global  dev  %s", netns, ipAddressInCIDR, broadcastAddress, portName)
	runSudo(cmdToRun, true, true, false)
}

func deleteVIF(portid string, netns string) {
	portName := portid[:11]
	deleteOVSPort(portName, "br-int")
	deleteNetNS(netns)
}

func createVIF(ipAddressInCIDR string, broadcastAddress string, portid string, macaddress string, netns string) {
	// Attach tap device to br-int
	portName := portid[:11]
	attachTapDeviceToOVSBridge(portName, portid, macaddress, "br-int")
	setTapDeviceMacAddress(portName, macaddress)
	initNetNS(netns)
	addTapDeviceToNetNS(portName, netns)
	applyIPAddressToTapDeviceInNetNS(ipAddressInCIDR, broadcastAddress, portName, netns)
}

func createVIFOnHost(portid string, macaddress string) {
	// Attach tap device to br-int
	portName := portid[:11]
	attachTapDeviceToOVSBridge(portName, portid, macaddress, "br-int")
	setTapDeviceMacAddress(portName, macaddress)
}

/* This will create a net namespace with the same name as that of the docker container */
func createNSForDockerContainer(container_id string) {
	var cmdToRun string
	// Ensure that netns folder exists
	cmdToRun = "mkdir -p /var/run/netns"
	runSudo(cmdToRun, true, true, false)

	txt := runSudoWithOutput("./findpid.sh "+container_id, false, true, false)
	//txt := runCmdWithOutput("source ~/ip.txt;docker $H inspect -f '{{ .State.Pid }}' " + container_id,false,true,false,true)
	n := len(txt)
	container_pid := strings.TrimSpace(string(txt[:n]))
	fmt.Println("PID for container is: " + container_pid)

	cmdToRun = fmt.Sprintf("ln -sf /proc/%s/ns/net /var/run/netns/%s", container_pid, container_id)
	runSudo(cmdToRun, true, true, false)
}
