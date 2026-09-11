package jcode

import (
	"strconv"
)

// JSON format of intermediate code written by pass1 and read by pass2.
type RouterData struct {
	Model         string     `json:"model"`
	ACLs          []*ACLInfo `json:"acls"`
	DoObjectgroup bool       `json:"do_objectgroup,omitzero"`
}

type ACLInfo struct {
	Name         string   `json:"name"`
	Rules        []*Rule  `json:"rules"`
	IntfRules    []*Rule  `json:"intf_rules"`
	OptNetworks  []string `json:"opt_networks,omitempty"`
	NoOptAddrs   []string `json:"no_opt_addrs,omitempty"`
	NeedProtect  []string `json:"need_protect,omitempty"`
	AddPermit    bool     `json:"add_permit,omitzero"`
	AddDeny      bool     `json:"add_deny,omitzero"`
	FilterAnySrc bool     `json:"filter_any_src,omitzero"`
	FilterOnly   []string `json:"filter_only,omitempty"`
	IsStdACL     bool     `json:"is_std_acl,omitzero"`
	IsCryptoACL  bool     `json:"is_crypto_acl,omitzero"`
	Tier         string   `json:"tier,omitzero"`
	VRF          string   `json:"vrf,omitzero"`
	LogDeny      string   `json:"log_deny,omitzero"`
}

type Rule struct {
	Deny         bool     `json:"deny,omitzero"`
	Src          []string `json:"src"`
	Dst          []string `json:"dst"`
	Prt          []string `json:"prt"`
	SrcRange     string   `json:"src_range,omitzero"`
	Log          string   `json:"log,omitzero"`
	OptSecondary bool     `json:"opt_secondary,omitzero"`
}

// GenPortName is used to create name of protocol with ports printed
// in Rule.Prt .
// This must be identical in pass1 and pass2.
func GenPortName(proto string, v1, v2 int) string {
	if v1 == v2 {
		return proto + " " + strconv.Itoa(v1)
	} else if v1 == 1 && v2 == 65535 {
		return proto
	} else {
		return proto + " " + strconv.Itoa(v1) + "-" + strconv.Itoa(v2)
	}
}
