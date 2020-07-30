package main

import (
	"bytes"
	"fmt"
	"net/http"

	nsl "github.com/dataparency-dev/natslib"
	"github.com/nats-io/nats.go"
)

var ebody = bytes.NewBufferString(`{
	"data": {
			"resourceType": "Patient",
			"id": "-20140000008325",
			"extension": [{
					"url": "https://bluebutton.cms.gov/resources/variables/race",
					"valueCoding": {
						"system": "https://bluebutton.cms.gov/resources/variables/race",
						"code": "1",
						"display": "White"
					}
				}
			],
			"identifier": [{
					"system": "https://bluebutton.cms.gov/resources/variables/bene_id",
					"value": "-20140000008325"
				}, {
					"system": "https://bluebutton.cms.gov/resources/identifier/hicn-hash",
					"value": "ee78989d1d9ba0b98f3cfbd52479f10c7631679c17563186f70fbef038cc9536"
				}
			],
			"name": [{
					"use": "usual",
					"family": "Doe",
					"given": ["Jane", "X"]
				}
			],
			"gender": "female",
			"birthDate": "2014-06-01",
			"address": [{
					"district": "999",
					"state": "15",
					"postalCode": "99999"
				}
			]
		}
	}`)

func main() {
	var rpc, ps string
	var status int
	nsl.ConnectAPI(nats.DefaultURL, nsl.DefaultServer)
//	ps, status = nsl.EntityRetrieve(nsl.DefaultServer, "sysadm", "sysadm", ps)
//	ps, _ = nsl.SysAdminRegister(nsl.DefaultServer, "sysadm", "DISP")
	fmt.Printf("sysadm passCode %v\n", ps)
	rpc, status = nsl.EntityRetrieve(nsl.DefaultServer, "req17", "sysadm", ps)
	fmt.Printf("status 1 %v err %s\n",status,rpc)
	if status != http.StatusOK {
		rpc, _ = nsl.EntityRegister("disp-requests", "req17", "DISP","admin","")
	}
	token := nsl.LoginAPI("disp-requests", "req17", rpc)
	fmt.Printf("passCode %v\ntoken %v\n", rpc, token)

	rpc, status = nsl.EntityRetrieve(nsl.DefaultServer, "user17", "req17", rpc)
	fmt.Printf("status 2 %v err %v\n",status,rpc)
	if status != http.StatusOK {
		_, _ = nsl.EntityRegister("disp-requests", "user17", "DISP","admin","")
	}
	rdid, status := nsl.RelationRegister(nsl.DefaultServer, "user17", "req17", rpc)
	fmt.Printf("status 3 %v\n",status)
	if status != http.StatusOK {
		fmt.Printf("relation register error %v\n", status)
	}
	dopts := make(nsl.Dopts, 1)
	nsl.SetDomain(dopts, "test")
	nsl.SetEntity(dopts, "clients")
	nsl.SetRDID(dopts, rdid)
	nsl.SetAspect(dopts, "claims")
	nslr := nsl.Post(nsl.DefaultServer, ebody.Bytes(), dopts)
	fmt.Printf("response %v\n", nslr.Response)
	nsl.SetTag(dopts, "data")
	nslr = nsl.Get(nsl.DefaultServer, dopts)
	fmt.Printf("get rs %v\n", nslr.Response)

}
