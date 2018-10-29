package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Jeffail/gabs"
	ldap "github.com/butonic/ldapserver"
	"github.com/go-fsnotify/fsnotify"
)

var jsonParsed *gabs.Container

func loadData(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	log.Printf("loaded %s", file)

	var tmpJson *gabs.Container
	tmpJson, err = gabs.ParseJSON(data)
	if err != nil {
		return err
	}
	jsonParsed = tmpJson
	log.Printf("parsed JSON")
	return nil
}

func main() {

	hostAndPort := flag.String("l", "127.0.0.1:10389", "host and port to listen for connections")
	dataFile := flag.String("d", "data.json", "json file with data to serve")
	flag.Parse()

	err := loadData(*dataFile)
	if err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}

	// create a new file watcher, based on https://medium.com/@skdomino/watch-this-file-watching-in-go-5b5a247cf71f
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("ERROR", err)
	}
	defer watcher.Close()

	//nch := make(chan bool)

	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				// TODO wait a sec before reparsing and ignore additional notifications in that time
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Printf("modified file: %v, %v, %#v", event.Name, event.Op, event)
					// reload json
					err := loadData(*dataFile)
					if err != nil {
						log.Printf("ERROR: %v", err)
					}
				}

				// watch for errors
			case err := <-watcher.Errors:
				log.Println("ERROR", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add(*dataFile); err != nil {
		log.Println("ERROR", err)
	}

	//<-nch

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
