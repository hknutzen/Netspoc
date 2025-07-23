package pass1

import (
	"cmp"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type chkpConfig struct {
	Rules    []*chkpRule
	Networks []*chkpNetwork
	Hosts    []*chkpHost
	Groups   []*chkpGroup
	TCP      []*chkpTCPUDP
	UDP      []*chkpTCPUDP
	//ICMP  []*chkpICMP
	//ICMP6 []*chkpICMP
	//SvOther       []*chkpSvOther
	GatewayRoutes map[string][]*chkpRoute
}

// Default value of attribute 'enabled' is true.
// But zero value of bool is false in Go.
// Hence we store the inverted value in attribute 'disabled'.
type invertedBool bool

type chkpRule struct {
	Name              string       `json:"name"`
	Layer             string       `json:"layer,omitempty"`
	Comments          string       `json:"comments,omitempty"`
	Action            chkpName     `json:"action"`
	Source            []chkpName   `json:"source"`
	Destination       []chkpName   `json:"destination"`
	Service           []chkpName   `json:"service"`
	Disabled          invertedBool `json:"enabled,omitempty"`
	SourceNegate      bool         `json:"source-negate,omitempty"`
	DestinationNegate bool         `json:"destination-negate,omitempty"`
	ServiceNegate     bool         `json:"service-negate,omitempty"`
	Track             *chkpTrack   `json:"track,omitempty"`
	InstallOn         []chkpName   `json:"install-on"`
	Position          interface{}  `json:"position,omitempty"`
	Append            bool         `json:"append,omitempty"` // From raw file.
	needed            bool
}
type chkpName string

type chkpTrack struct {
	Accounting            bool     `json:"accounting,omitempty"`
	Alert                 string   `json:"alert,omitempty"`
	EnableFirewallSession bool     `json:"enable-firewall-session,omitempty"`
	PerConnection         bool     `json:"per-connection,omitempty"`
	PerSession            bool     `json:"per-session,omitempty"`
	Type                  chkpName `json:"type,omitempty"`
}

type chkpObject struct {
	Name      string `json:"name"`
	Comments  string `json:"comments,omitempty"`
	ReadOnly  bool   `json:"read-only,omitempty"`
	needed    bool
	deletable bool
}

type chkpNetwork struct {
	chkpObject
	Subnet4     string `json:"subnet4,omitempty"`
	Subnet6     string `json:"subnet6,omitempty"`
	MaskLength4 int    `json:"mask-length4,omitempty"`
	MaskLength6 int    `json:"mask-length6,omitempty"`
}

type chkpHost struct {
	chkpObject
	IPv4Address string `json:"ipv4-address,omitempty"`
	IPv6Address string `json:"ipv6-address,omitempty"`
}

type chkpGroup struct {
	chkpObject
	Members []chkpName `json:"members"`
}

type chkpTCPUDP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type chkpICMP struct {
	chkpObject
	IcmpType *int `json:"icmp-type"`
	IcmpCode *int `json:"icmp-code,omitempty"`
}

type chkpSvOther struct {
	chkpObject
	IpProtocol int    `json:"ip-protocol"`
	Match      string `json:"match,omitempty"`
}

type chkpRoute struct {
	Address    string        `json:"address"`
	MaskLength int           `json:"mask-length"`
	Type       string        `json:"type"`
	NextHop    []chkpGateway `json:"next-hop"`
}

type chkpGateway struct {
	Gateway string `json:"gateway"`
}

func collectCheckpointRoutes(vrfMembers []*router, config *chkpConfig) {
	m := make(map[string][]*chkpRoute)
	for _, r := range vrfMembers {
		var routes []*chkpRoute
		for _, intf := range r.interfaces {
			if intf.routing != nil {
				continue
			}
			for natNet, hopList := range intf.routes {
				if natNet.hidden {
					continue
				}

				// This is unambiguous, because only a single static
				// route is allowed for each network.
				hop := hopList[0]
				r := &chkpRoute{
					Address:    natNet.ipp.Addr().String(),
					MaskLength: natNet.ipp.Bits(),
					Type:       "gateway",
					NextHop:    []chkpGateway{{hop.ip.String()}},
				}
				routes = append(routes, r)
			}
		}
		slices.SortFunc(routes, func(a, b *chkpRoute) int {
			if ret := cmp.Compare(a.Address, b.Address); ret != 0 {
				return ret
			}
			return cmp.Compare(a.MaskLength, b.MaskLength)
		})
		m[r.vrf] = routes
	}
	config.GatewayRoutes = m
}

func (c *spoc) collectCheckpointACLs(vrfMembers []*router, config *chkpConfig) {
	hosts := make(map[string]*chkpHost)
	networks := make(map[string]*chkpNetwork)
	tcpudp := make(map[*proto]*chkpTCPUDP)
	for _, r := range vrfMembers {
		rules := make(map[string]*chkpRule)
		for _, hw := range r.hardware {

			// Ignore if all logical interfaces are loopback interfaces.
			if hw.loopback {
				continue
			}

			for _, rule := range hw.rules {
				srv := rule.rule.service

				var action string
				if rule.deny {
					action = "Drop"
				} else {
					action = "Allow"
				}
				srvName, _ := strings.CutPrefix(srv.name, "service:")
				name := srvName

				//Generate unique name for rule for each "install-on" instance
				for i := 2; rules[name] != nil; i++ {
					name = srvName + "-" + strconv.Itoa(i)
				}

				rules[name] = &chkpRule{
					Name:      name,
					Comments:  srv.description,
					Action:    chkpName(action),
					InstallOn: []chkpName{chkpName(r.vrf)},
				}

				handleRuleObject := func(obj someObj) string {
					addr := obj.address(hw.natMap)
					name := strings.Replace(obj.String(), ":", "_", -1)
					objName := name
					if addr.IsSingleIP() {
						for i := 2; hosts[objName] != nil || networks[objName] != nil; i++ {
							if hosts[objName] != nil &&
								(addr.Addr().String() == hosts[objName].IPv4Address ||
									addr.Addr().String() == hosts[objName].IPv6Address) {
								break
							}
							objName = name + "_part-" + strconv.Itoa(i)
						}

						if _, found := hosts[objName]; !found {
							ruleHost := &chkpHost{}
							ruleHost.Name = objName
							if addr.Addr().Is6() {
								ruleHost.IPv6Address = addr.Addr().String()
							} else {
								ruleHost.IPv4Address = addr.Addr().String()
							}
							hosts[objName] = ruleHost
						}
					} else {
						for i := 2; networks[objName] != nil || hosts[objName] != nil; i++ {
							if networks[objName] != nil &&
								(addr.Addr().String() == networks[objName].Subnet4 && addr.Bits() == networks[objName].MaskLength4 ||
									addr.Addr().String() == networks[objName].Subnet6 && addr.Bits() == networks[objName].MaskLength6) {
								break
							}
							objName = name + "_part-" + strconv.Itoa(i)
						}
						if _, found := networks[objName]; !found {
							ruleNet := &chkpNetwork{}
							ruleNet.Name = objName
							if addr.Addr().Is6() {
								ruleNet.Subnet6 = addr.Addr().String()
								ruleNet.MaskLength6 = addr.Bits()
							} else {
								ruleNet.Subnet4 = addr.Addr().String()
								ruleNet.MaskLength4 = addr.Bits()
							}
							networks[objName] = ruleNet
						}
					}
					return objName
				}
				for _, src := range rule.src {
					objName := handleRuleObject(src)
					rules[name].Source = append(rules[name].Source, chkpName(objName))
				}
				for _, dst := range rule.dst {
					objName := handleRuleObject(dst)
					rules[name].Destination = append(rules[name].Destination, chkpName(objName))
				}
				for _, prt := range rule.prt {
					prtName := strings.ReplaceAll(prt.name, " ", "_")
					if prt.proto == "icmp" {
						switch prt.icmpType {
						case 0:
							prtName = "echo-reply"
						case 3:
							prtName = "dest-unreach"
						case 4:
							prtName = "source-quench"
						case 5:
							prtName = "redirect"
						case 8:
							prtName = "echo-request"
						case 11:
							prtName = "time-exceeded"
						case 12:
							prtName = "param-prblm"
						case 13:
							prtName = "timestamp"
						case 14:
							prtName = "timestamp-reply"
						case 15:
							prtName = "info-req"
						case 16:
							prtName = "info-reply"
						case 17:
							prtName = "mask-request"
						case 18:
							prtName = "mask-reply"
						}
					} else if _, found := tcpudp[prt]; !found {
						rulePrt := &chkpTCPUDP{}
						rulePrt.Name = prtName
						rulePrt.Port = strconv.Itoa(prt.ports[0])
						if prt.ports[0] != prt.ports[1] {
							rulePrt.Port += "-" + strconv.Itoa(prt.ports[1])
						}
						tcpudp[prt] = rulePrt
					}
					rules[name].Service = append(rules[name].Service, chkpName(prtName))
				}
			}
		}
		// Add rules for each vrf / install-on
		for _, k := range slices.Sorted(maps.Keys(rules)) {
			rule := rules[k]
			// Check for possible group creation, if at least 100 elements present.
			checkGroup := func(l *[]chkpName, name string) {
				if len(*l) >= 100 {
					//To avoid same Groupname for source and destination of same rule
					groupName := name + rule.Name
					ruleGroup := &chkpGroup{
						chkpObject: chkpObject{
							Name: groupName,
						},
						Members: make([]chkpName, len(*l)),
					}
					for i, m := range *l {
						ruleGroup.Members[i] = m
					}
					config.Groups = append(config.Groups, ruleGroup)
					*l = []chkpName{chkpName(groupName)}
				}
			}

			slices.Sort(rule.Source)
			rule.Source = slices.Compact(rule.Source)
			checkGroup(&rule.Source, "SrcGrp_")

			slices.Sort(rule.Destination)
			rule.Destination = slices.Compact(rule.Destination)
			checkGroup(&rule.Destination, "DstGrp_")
			config.Rules = append(config.Rules, rules[k])
		}
	}
	for _, k := range slices.Sorted(maps.Keys(hosts)) {
		config.Hosts = append(config.Hosts, hosts[k])
	}
	for _, k := range slices.Sorted(maps.Keys(networks)) {
		config.Networks = append(config.Networks, networks[k])
	}
	for _, k := range slices.SortedFunc(maps.Keys(tcpudp), func(a, b *proto) int {
		if cm := cmp.Compare(a.ports[1], b.ports[1]); cm != 0 {
			return cm
		}
		return cmp.Compare(a.ports[0], b.ports[0])
	}) {
		switch k.proto {
		case "tcp":
			config.TCP = append(config.TCP, tcpudp[k])
		case "udp":
			config.UDP = append(config.UDP, tcpudp[k])
		}
	}
}

func (c *spoc) printCheckpoint(r *router, dir string) {
	path := r.deviceName
	if r.ipV6 {
		path = "ipv6/" + path
	}

	// Collect VRF members.
	vrfMembers := r.vrfMembers
	if vrfMembers == nil {
		vrfMembers = []*router{r}
	}

	// Print info file in JSON format.
	infoData := c.getCodeInfo(vrfMembers)
	c.writeJson(filepath.Join(dir, path+".info"), infoData)

	config := &chkpConfig{}
	collectCheckpointRoutes(vrfMembers, config)
	c.collectCheckpointACLs(vrfMembers, config)

	// File for router
	routerFile := filepath.Join(dir, path)
	fd, err := os.OpenFile(routerFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		c.abort("Can't %v", err)
	}
	defer fd.Close()

	enc := json.NewEncoder(fd)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	enc.Encode(config)
}
