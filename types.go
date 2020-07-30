package natsclient

const DefaultServer = "disp-requests"

type Dopts map[string]interface{}

type NATSEDIDRetEntry struct {
	Identity     string   `json:"identity"`
	PassCode     string   `json:"pCode"`
	EntityAccess string   `json:"entityAccess"`
	Roles        []string `json:"roles"`
	Groups       []string `json:"groups"`
}

type NATSResponseHeader struct {
	Created      bool   `json:"created,omitempty"`
	Timestamp    int64  `json:"timestamp,omitempty"`
	Path         string `json:"path,omitempty"`
	Doc          string `json:"docId,omitempty"`
	DocVersion   string `json:"docVersion,omitempty"`
	Status       int    `json:"status"`
	ErrorStr     string `json:"error_str,omitempty"`
	ServerID     string `json:"serverID,omitempty"`
	Chunks       int    `json:"chunks,omitempty"`
	EncryptedHdr []byte `json:"encrypted_hdr,omitempty"`
}

type NATSReqHeader struct {
	Mode          string                 `json:"mode"`
	Path          string                 `json:"path"`
	Flags         map[string]interface{} `json:"flags"`
	Authorization string                 `json:"authorization"`
	Accept        string                 `json:"accept"`
}

type NATSRequest struct {
	Header NATSReqHeader `json:"header"`
	Body   []byte        `json:"body"`
}

type NATSResponse struct {
	Header   NATSResponseHeader `json:"header"`
	Response string             `json:"response"`
}
