package natsclient

import (
	"encoding/json"
	"fmt"
	_ "fmt"
	"log"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	libnc *nats.Conn
	//token string
)

func init() {

	// Connect Options.

}

func LoginAPI(server, user, passCode string) string {

	type User struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Expires  uint64 `json:"expires"`
	}

	type Token struct {
		Token string `json:"token"`
	}

	var token string

	tk := &Token{}

	tbodyS := &User{}
	tbodyS.Username = user
	tbodyS.Password = passCode
	tbodyS.Expires = 999999999999
	tbody, err := json.Marshal(tbodyS)

	thdr := NATSReqHeader{
		Mode: "POST",
		Path: "/api/login",
	}
	trec := &NATSRequest{
		Header: thdr,
		Body:   tbody,
	}
	payload, err := json.Marshal(trec)
	msg, err := libnc.Request(server, payload, 10*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		err = json.Unmarshal([]byte(response.Response), tk)
		token = string(tk.Token)
		//fmt.Printf("token '%v'\n",token)
	}

	return token
}

func SysAdminRegister(server, identity, passCode, token, roles, groups string) (passCd string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity
	eflags["passCode"] = passCode
	eflags["roles"] = roles
	eflags["groups"] = groups

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/sysadm/register",
		Flags:         eflags,
		Authorization: token,
	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	msg, err := libnc.Request(server, payload, 20*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		if response.Header.Status != 200 {
			passCd = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			passCd = response.Response
			status = response.Header.Status
		}
	}
	return passCd, status
}

func EntityRegister(server, identity, token, roles, groups string) (passCd string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity
	eflags["roles"] = roles
	eflags["groups"] = groups

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/entity/register",
		Flags:         eflags,
		Authorization: token,
	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	msg, err := libnc.Request(server, payload, 20*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		if response.Header.Status != 200 {
			passCd = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			passCd = response.Response
			status = response.Header.Status
		}
	}
	return passCd, status
}

func RelationRegister(server, identity, token string) (resp string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/relation/register",
		Flags:         eflags,
		Authorization: token,
	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	msg, err := libnc.Request(server, payload, 20*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = response.Response
			status = response.Header.Status
		}
	}
	return resp, status
}

func EntityRetrieve(server, identity, token string) (resp string, status int) {
	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	ehdr := NATSReqHeader{
		Mode:          "GET",
		Path:          "/entity/retrieve",
		Flags:         eflags,
		Authorization: token,
	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	msg, err := libnc.Request(server, payload, 10*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = response.Response
			status = response.Header.Status
		}
	}
	return resp, status
}

func SetTag(dopts Dopts, val string) {
	dopts["k"] = val
}

func SetVal(dopts Dopts, val string) {
	dopts["v"] = val
}

func SetMatch(dopts Dopts, val string) {
	dopts["q"] = val
}

func SetWithHeaders(dopts Dopts, val bool) {
	dopts["withHeades"] = val
}

func SetEntityAccess(dopts Dopts, val string) {
	dopts["entityAccess"] = val
}

func SetNoHeaders(dopts Dopts, val bool) {
	dopts["noHeaders"] = val
}

func SetTimestamp(dopts Dopts, val string) {
	dopts["timestamp"] = val
}

func SetEncryptDataPKey(dopts Dopts, val string) {
	dopts["encryptDataPKey"] = val
}

func SetDomain(dopts Dopts, val string) {
	dopts["domain"] = val
}

func SetEntity(dopts Dopts, val string) {
	dopts["entity"] = val
}

func SetRDID(dopts Dopts, val string) {
	dopts["rdid"] = val
}

func SetAspect(dopts Dopts, val string) {
	dopts["aspect"] = val
}

func SetCount(dopts Dopts, val bool) {
	dopts["count"] = val
}

func SetRoles(dopts Dopts, val string) {
	dopts["roles"] = val
}

func SetGroups(dopts Dopts, val string) {
	dopts["groups"] = val
}

func Get(server string, dopts Dopts, token string) *NATSResponse {
	dflags := make(map[string]interface{})
	if dopts["withHeaders"] != nil {
		dflags["withHeaders"] = dopts["withHeaders"].(bool)
	}
	if dopts["noHeaders"] != nil {
		dflags["noHeaders"] = dopts["noHeaders"].(bool)
	}
	if dopts["timestamp"] != nil {
		dflags["timestamp"] = dopts["timestamp"].(string)
	}
	if dopts["encryptDataPKey"] != nil {
		dflags["encryptDataPKey"] = dopts["encryptDataPKey"].(string)
	}
	if dopts["domain"] != nil {
		dflags["domain"] = dopts["domain"].(string)
	}
	if dopts["entity"] != nil {
		dflags["entity"] = dopts["entity"].(string)
	}
	if dopts["rdid"] != nil {
		dflags["rdid"] = dopts["rdid"].(string)
	}
	if dopts["aspect"] != nil {
		dflags["aspect"] = dopts["aspect"].(string)
	}
	if dopts["k"] != nil {
		dflags["k"] = dopts["k"].(string)
	}
	if dopts["v"] != nil {
		dflags["v"] = dopts["v"].(string)
	}
	if dopts["q"] != nil {
		dflags["q"] = dopts["q"].(string)
	}
	if dopts["count"] != nil {
		dflags["count"] = dopts["count"].(bool)
	}

	mode := "GET"
	dhdr := NATSReqHeader{
		Mode:          mode,
		Flags:         dflags,
		Authorization: token,
	}
	if dflags["token"] == nil {
		dhdr.Path = fmt.Sprintf("/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["aspect"])

	} else {
		dhdr.Path = fmt.Sprintf("/%v/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["rdid"], dflags["aspect"])
	}

	replyTo := libnc.NewRespInbox()
	dhdr.ReplyTo = replyTo

	drec := &NATSRequest{
		Header: dhdr,
		Body:   nil,
	}

	response := &NATSResponse{}
	payload, err := json.Marshal(drec)

	_, err = libnc.Request(server, payload, 2*time.Minute)
	if err != nil {
		response.Header.Status = http.StatusBadGateway
		if libnc.LastError() != nil {
			log.Printf("%v for request", libnc.LastError())
			response.Header.ErrorStr = fmt.Sprintf("%v for request", libnc.LastError())
		}
		log.Printf("%v for request", err)
		response.Header.ErrorStr = fmt.Sprintf("%v for request", err)
	}
	sub, err := libnc.Subscribe(replyTo, func (msg *nats.Msg)  {
		err = json.Unmarshal(msg.Data, response)
	})

	err = sub.Unsubscribe()
	if err != nil {
		response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n",err)
	}

	//response.Header.Status = http.StatusOK
	return response
}

func Post(server string, body []byte, dopts Dopts, token string) *NATSResponse {

	dflags := make(map[string]interface{})
	if dopts["entityAccess"] != nil {
		dflags["entityAccess"] = dopts["entityAccess"].(string)
	}
	if dopts["withHeader"] != nil {
		dflags["withHeader"] = dopts["withHeader"].(bool)
	}
	if dopts["domain"] != nil {
		dflags["domain"] = dopts["domain"].(string)
	}
	if dopts["entity"] != nil {
		dflags["entity"] = dopts["entity"].(string)
	}
	if dopts["rdid"] != nil {
		dflags["rdid"] = dopts["rdid"].(string)
	}
	if dopts["aspect"] != nil {
		dflags["aspect"] = dopts["aspect"].(string)
	}

	mode := "POST"
	dhdr := NATSReqHeader{
		Mode: mode,
		Path: fmt.Sprintf("/%v/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["rdid"], dflags["aspect"]),
		Flags:         dflags,
		Authorization: token,
	}

	replyTo := libnc.NewRespInbox()
	dhdr.ReplyTo = replyTo

	drec := &NATSRequest{
		Header: dhdr,
		Body:   body,
	}

	response := &NATSResponse{}
	payload, err := json.Marshal(drec)

	_, err = libnc.Request(server, payload, 2*time.Minute)
	if err != nil {
		response.Header.Status = http.StatusBadGateway
		if libnc.LastError() != nil {
			log.Printf("%v for request", libnc.LastError())
			response.Header.ErrorStr = fmt.Sprintf("%v for request", libnc.LastError())
		}
		log.Printf("%v for request", err)
		response.Header.ErrorStr = fmt.Sprintf("%v for request", err)
		response.Header.Status = http.StatusGatewayTimeout
		return response

	}

	sub, err := libnc.Subscribe(replyTo, func (msg *nats.Msg)  {
		err = json.Unmarshal(msg.Data, response)
	})

	err = sub.Unsubscribe()
	if err != nil {
		response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n",err)
	}

	response.Header.Status = http.StatusOK
	return response
}

func ConnectAPI(url, srvtopic string) *nats.Conn {

	opts := []nats.Option{nats.Name("NATS Lib")}
	opts = setupConnOptions(opts)

	// Connect to NATS
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		log.Fatal(err)
	}

	libnc = nc
	return libnc

}

func setupConnOptions(opts []nats.Option) []nats.Option {
	totalWait := 10 * time.Minute
	reconnectDelay := time.Second

	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		log.Printf("Disconnected due to: %s, will attempt reconnects for %.0fm", err, totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		log.Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		log.Fatalf("Exiting: %v", nc.LastError())
	}))
	return opts
}
