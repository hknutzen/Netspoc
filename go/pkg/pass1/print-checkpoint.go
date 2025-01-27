package pass1

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type chkpConfig struct {
	Rules    []*chkpRule
	Networks []*chkpNetwork
	Hosts    []*chkpHost
	//Groups        []*chkpGroup
	//TCP           []*chkpTCP
	//UDP           []*chkpUDP
	//ICMP          []*chkpICMP
	//ICMP6         []*chkpICMP6
	//SvOther       []*chkpSvOther
	GatewayRoutes map[string][]*chkpRoute
	//GatewayIP     map[string]string
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

type chkpTCP struct {
	chkpObject
	Port       string `json:"port"`
	SourcePort string `json:"source-port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type chkpUDP struct {
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

type chkpICMP6 struct {
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
		m[r.vrf] = routes
	}
	config.GatewayRoutes = m
}

func (c *spoc) collectCheckpointACLs(vrfMembers []*router, config *chkpConfig) {
	var rules []*chkpRule
	hosts := make(map[string]*chkpHost)
	networks := make(map[string]*chkpNetwork)
	for _, r := range vrfMembers {
		for _, hw := range r.hardware {

			// Ignore if all logical interfaces are loopback interfaces.
			if hw.loopback {
				continue
			}

			for _, rule := range hw.rules {
				var action chkpName
				if rule.deny {
					action = "Drop"
				} else {
					action = "Allow"
				}

				var source, destination []chkpName
				for _, src := range rule.src {
					//name := rule.rule.service.name
					addr := src.address(hw.natMap)
					if addr.IsSingleIP() {
						if _, ok := hosts[src.String()]; !ok {
							hosts[addr.String()] = &chkpHost{}
						}
					} else {
						if _, ok := networks[src.String()]; !ok {
							networks[src.String()] = &chkpNetwork{}
						}
					}
					source = append(source)
				}
				for _, d := range rule.dst {
					destination = append(destination, chkpName(d.String()))
				}
				rules = append(rules, &chkpRule{
					Name:        rule.rule.service.name,
					Comments:    rule.rule.service.description,
					Action:      action,
					Source:      source,
					Destination: destination,
					InstallOn:   []chkpName{chkpName(r.vrf)},
				})
			}
		}
	}
	config.Rules = rules
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

	//result, err := json.Marshal(config)
	if err != nil {
		c.err("Can't: %v", err)
	}

	enc := json.NewEncoder(fd)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	enc.Encode(config)
}
