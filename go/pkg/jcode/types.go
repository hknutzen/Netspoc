package jcode

// JSON format of intermediate code written by pass1 and read by pass2.
type RouterData struct {
	Model         string     `json:"model"`
	ACLs          []*ACLInfo `json:"acls"`
	FilterOnly    []string   `json:"filter_only,omitempty"`
	DoObjectgroup int        `json:"do_objectgroup,omitempty"`
	LogDeny       string     `json:"log_deny,omitempty"`
}

type ACLInfo struct {
	Name         string   `json:"name"`
	Rules        []*Rule  `json:"rules"`
	IntfRules    []*Rule  `json:"intf_rules"`
	OptNetworks  []string `json:"opt_networks,omitempty"`
	NoOptAddrs   []string `json:"no_opt_addrs,omitempty"`
	NeedProtect  []string `json:"need_protect,omitempty"`
	AddPermit    int      `json:"add_permit,omitempty"`
	AddDeny      int      `json:"add_deny,omitempty"`
	FilterAnySrc int      `json:"filter_any_src,omitempty"`
	IsStdACL     int      `json:"is_std_acl,omitempty"`
	IsCryptoACL  int      `json:"is_crypto_acl,omitempty"`
}

type Rule struct {
	Deny         int      `json:"deny,omitempty"`
	Src          []string `json:"src"`
	Dst          []string `json:"dst"`
	Prt          []string `json:"prt"`
	SrcRange     string   `json:"src_range,omitempty"`
	Log          string   `json:"log,omitempty"`
	OptSecondary int      `json:"opt_secondary,omitempty"`
}
