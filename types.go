package natsclient

const DefaultServer = "disp-requests"

type Dopts map[string]interface{}

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
	Path          string                 `json:"path,omitempty"`
	Flags         map[string]interface{} `json:"flags,omitempty"`
	Authorization string                 `json:"authorization,omitempty"`
	Accept        string                 `json:"accept,omitempty"`
	ReplyTo       string                 `json:"reply_to,omitempty"`
}

type NATSRequest struct {
	Header NATSReqHeader `json:"header"`
	Body   []byte        `json:"body"`
}

type NATSResponse struct {
	Header   NATSResponseHeader `json:"header"`
	Response string             `json:"response"`
}

type datarec struct {
	value interface{}
}

type grspHeaderResults struct {
	Data datarec `json:"data"`
}

type qrspHeader struct {
	DocId      string              `json:"docId"`
	DocVersion string              `json:"docVersion"`
	Created    int64               `json:"created"`
	Results    []grspHeaderResults `json:"results"`
}
type queryResponse struct {
	Docs []qrspHeader `json:"docs"`
}

type NATSSCData struct {
	Response queryResponse
}
