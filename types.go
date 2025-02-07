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
	Path          string                 `json:"path"`
	Flags         map[string]interface{} `json:"flags"`
	Authorization string                 `json:"authorization"`
	Accept        string                 `json:"accept"`
	ReplyTo       string                 `json:"reply_to"`
	SessPubkey    string                 `json:"sessPubkey,omitempty"`
}

type NATSRequest struct {
	Header NATSReqHeader `json:"header"`
	Body   []byte        `json:"body"`
}

type NATSResponse struct {
	Header   NATSResponseHeader `json:"header"`
	Response []byte             `json:"response"`
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
}

type matchspec struct {
	Roles  []string `json:"roles"`
	Groups []string `json:"groups"`
}

type condspec struct {
	Matches matchspec
}

type spec struct {
	Condition condspec
}

type fieldSpec struct {
	FName string `json:"fieldname"`
	Spec  spec   `json:"spec"`
}

type header struct {
	Name   string      `json:"name"`
	Fields []fieldSpec `json:"fields"`
}
type ACTemplate struct {
	Template header `json:"template"`
}
