package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	_ "github.com/dataparency-dev/natsclient"
)

//var version	"0.0.1"

func main () {
	fmt.Printf("Nats Tester v%v\n",version)
}