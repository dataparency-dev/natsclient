package natsclient

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	_ "golang.org/x/crypto/openpgp"
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

	tk := Token{}

	tbodyS := User{
		Username: user,
		Password: passCode,
		Expires:  999999999999,
	}
	tbody, err := json.Marshal(tbodyS)
	if err != nil {
		fmt.Printf("tbody err %v\n",err)
	}

	thdr := NATSReqHeader{
		Mode: "POST",
		Path: "/api/login",
	}
	trec := &NATSRequest{
		Header: thdr,
		Body:   tbody,
	}
	payload, err := json.Marshal(trec)
	if err != nil {
		fmt.Printf("trec err %v\n",err)
	}
	fmt.Printf("payload %v\n", string(payload))
	msg, err := libnc.Request(server, payload, 20*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		err = json.Unmarshal(msg.Data, response)
		//fmt.Printf("response %v\n",response)
		if response.Header.Status != http.StatusOK {
			return ""
		}
		err = json.Unmarshal([]byte(response.Response), tk)
		//fmt.Printf("resp.response %v header %v\n",response.Response,response.Header)
		token = string(tk.Token)
		//fmt.Printf("token '%v'\n",token)
	} else {
		return ""
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

func RelationRetrieve(server, identity, token string) (resp string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	ehdr := NATSReqHeader{
		Mode:          "GET",
		Path:          "/relation/retrieve",
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

	status = http.StatusBadRequest
	resp = ""
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
	//fmt.Printf("req resp %v\n",m)
	//err = libnc.Publish(server, payload)
	if err != nil {
		response.Header.Status = http.StatusBadGateway
		if libnc.LastError() != nil {
			log.Printf("%v for request", libnc.LastError())
			response.Header.ErrorStr = fmt.Sprintf("%v for request", libnc.LastError())
		}
		log.Printf("%v for request", err)
		response.Header.ErrorStr = fmt.Sprintf("%v for request", err)
	}
	s, err := libnc.SubscribeSync(replyTo)
	if err == nil {
		msg, err := s.NextMsg(2 * time.Minute)
		if err != nil {
			response.Header.Status = http.StatusRequestTimeout
			response.Header.ErrorStr = fmt.Sprintf("nextmsg err %v\n", err)
		} else {
			err = json.Unmarshal(msg.Data, response)
			if err != nil {
				response.Header.ErrorStr = fmt.Sprintf("unmarshal err %v\n", err)
			}
		}
		err = s.Unsubscribe()
		if err != nil {
			response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n", err)
		}

		return response
	}

	//response.Header.Status = http.StatusOK
	response.Header.Status = http.StatusBadRequest
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
	}

	s, err := libnc.SubscribeSync(replyTo)
	if err == nil {
		msg, err := s.NextMsg(20 * time.Minute)
		if err != nil {
			response.Header.ErrorStr = fmt.Sprintf("response err %v", err)
			response.Header.Status = http.StatusRequestTimeout
		} else {
			err = json.Unmarshal(msg.Data, response)
			if err != nil {
				response.Header.ErrorStr = fmt.Sprintf("unmarshal err %v\n", err)
			}
			//fmt.Printf("resp %v\n",response.Response)
			response.Header.Status = http.StatusOK
		}

		err = s.Unsubscribe()
		if err != nil {
			response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n", err)
		}

		return response
	}

	response.Header.Status = http.StatusBadRequest
	return response
}

func SCCheck(server, channel, token, rdid string) error {
	// get recvd message replyTo message

	dflags := make(map[string]interface{})
	SetDomain(dflags,"SecureChannel")
	SetEntity(dflags, "Channels")
	SetRDID(dflags,rdid)
	SetAspect(dflags, channel)
	SetTag(dflags, "data")
	rsp := Get(server, dflags, token)
	rspData := NATSResponse{}
	err := json.Unmarshal([]byte(rsp.Response), &rspData); if err != nil {
		return fmt.Errorf("unmarshall err %v", err)
	}
	if rspData.Header.Status != 200 {
		return fmt.Errorf("invalid access %v", rspData.Header.Status)
	}
	return nil
}

func processChannelReceivedMsg(msg *nats.Msg) ([]byte, error) {

	return msg.Data, nil
}

func SecureChannelQueueSubscribe(server string, channel string, token, rdid string) ([]byte, error) {
	log.Printf("Connecting secure channel %s\n",channel)
	var err error
	if err = SCCheck(server, channel, token, rdid); err != nil {
		log.Printf("Error: no access %s\n", err)
		return []byte(""), err
	}
	msgs := channel + ":MsgAvail"
	var msgData []byte
	type msgAvail struct {
		Topic	string `json:"topic"`
		Key 	string `json:"key"`
	}
	ma := &msgAvail{}
	// Use a WaitGroup to wait for a message to arrive
	wg := sync.WaitGroup{}
	wg.Add(1)

	// Subscribe to MsgAvail topic
	if _, err := libnc.Subscribe(msgs, func(m *nats.Msg) {
		_ = json.Unmarshal(m.Data,ma)
		var sub *nats.Subscription
		// subscribe to hidden topic for message received
		sub, err = libnc.Subscribe(ma.Topic, func(m *nats.Msg) {
			if err != nil {
				msgData = []byte("")
			}
			msgData = m.Data
			if err := sub.Unsubscribe(); err != nil {
				log.Printf("error unsubscribing %v\n",err)
			}
		})
		wg.Done()
	}); err != nil {
		log.Printf("subscribe error: %v\n",err)
	}

	// Wait for a message to come in
	wg.Wait()

	return msgData, err

}

func SecureChannelPublish(m *nats.Msg, server string, channel string,
							token, rdid string, expireSecs int64) error {
	log.Printf("Publishing secure channel %s\n",channel)
	if err := SCCheck(server, channel, token, rdid); err != nil {
		log.Printf("Error: %s\n", err)
		return err
	}
	receiveTopic := libnc.NewRespInbox()		// publish to temp uniquely named receive topic
	m.Subject = receiveTopic
	if err := libnc.PublishMsg(m); err != nil {
		log.Printf("Error: %s\n", err)
		return err
	}
	msgKey := libnc.NewRespInbox()	// create unique message key
	m.Subject = channel + ":MsgAvail"	// publish to MsgAvail topic
	m.Data = []byte(msgKey)		// set message Data to temp uniquely named receive topic key
								// by which to lookup in D-DDN subscriber received MsgAvail
	if err := libnc.PublishMsg(m); err != nil {	// publish message to channel MsgAvail topic
		log.Printf("Error: %s\n", err)
		return err
	}
	// POST to channel MsgAvail entity entry for subscriber later lookup
	var data []byte
	dflags := make(map[string]interface{})
	SetDomain(dflags,"SecureChannel")
	SetEntity(dflags, "Channels")
	SetRDID(dflags,rdid)
	SetAspect(dflags, channel)
	//SetExpiry(dflags, expireSecs)  TODO: create SetExpiry function
	rsp := Post(server,data,dflags,token)
	if rsp.Header.Status != http.StatusOK {
		err := fmt.Errorf("error %v\n",rsp.Header.Status)
		return err
	}

	return nil

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
