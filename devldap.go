package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Jeffail/gabs"
	ldap "github.com/vjeantet/ldapserver"
)

var jsonParsed *gabs.Container

func main() {

	hostAndPort := flag.String("l", "127.0.0.1:10389", "host and port to listen for connections")
	dataFile := flag.String("d", "data.json", "json file with data to serve")
	flag.Parse()

	data, err := ioutil.ReadFile(*dataFile)
	if err != nil {
        fmt.Printf("File error: %v\n", err)
        os.Exit(1)
    }

	jsonParsed, err = gabs.ParseJSON(data)
	if err != nil {
        fmt.Printf("Parse error: %v\n", err)
        os.Exit(1)
    }
	log.Printf("serving %s", *dataFile)

	//Create a new LDAP Server
	server := ldap.NewServer()

	//Create routes bindings
	routes := ldap.NewRouteMux()
	routes.NotFound(handleNotFound)
	routes.Abandon(handleAbandon)
	routes.Bind(handleBind)

	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")

	routes.Extended(handleExtended).Label("Ext - Generic")

	routes.Search(handleSearch).Label("Search - Generic")

	//Attach routes to server
	server.Handle(routes)

	// listen on 10389 and serve
	go server.ListenAndServe(*hostAndPort)

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}