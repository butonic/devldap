package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/Jeffail/gabs"
	ldap "github.com/vjeantet/ldapserver"
	"github.com/vjeantet/goldap/message"
)

var jsonParsed *gabs.Container


func handleNotFound(w ldap.ResponseWriter, r *ldap.Message) {
	switch r.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
	var req = m.GetAbandonRequest()
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		log.Printf("Abandon signal sent to request processor [messageID=%d]", int(req))
	}
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		password := jsonParsed.Search(string(r.Name()), "userpassword").Data()
		log.Printf("User=%s, password=%v", string(r.Name()), password)

		if password == nil {
			log.Printf("User=%s, has no userpassword", string(r.Name()))
		} else if string(r.AuthenticationSimple()) == password.(string) {
			w.Write(res)
			return
		}
		log.Printf("Bind failed User=%s, Pass=%#v", string(r.Name()), r.Authentication())
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}

	w.Write(res)
}

func handleExtended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()
	log.Printf("Extended request received, name=%s", r.RequestName())
	log.Printf("Extended request received, value=%x", r.RequestValue())
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	log.Printf("Request BaseDn=%s", r.BaseObject())	
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	e := ldap.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "Valère JEANTET")
	e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("objectClass", "top", "inetOrgPerson", "extensibleObject")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("namingContexts", "o=My Company, c=US")
	// e.AddAttribute("subschemaSubentry", "cn=schema")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")
	// e.AddAttribute("supportedFeatures", "1.3.6.1.4.1.4203.1.5.1")
	// e.AddAttribute("supportedControl", "2.16.840.1.113730.3.4.3", "1.3.6.1.4.1.4203.1.10.1", "2.16.840.1.113730.3.4.2", "1.3.6.1.4.1.4203.1.9.1.4", "1.3.6.1.4.1.42.2.27.8.5.1", "1.3.6.1.4.1.4203.1.9.1.1", "1.3.6.1.4.1.4203.1.9.1.3", "1.3.6.1.4.1.4203.1.9.1.2", "1.3.6.1.4.1.18060.0.0.1", "2.16.840.1.113730.3.4.7", "1.2.840.113556.1.4.319")
	// e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")
	// e.AddAttribute("supportedSASLMechanisms", "NTLM", "GSSAPI", "GSS-SPNEGO", "CRAM-MD5", "SIMPLE", "DIGEST-MD5")
	e.AddAttribute("entryUUID", "f290425c-8272-4e62-8a67-92b06f38dbf5")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func handleSearchMyCompany(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("handleSearchMyCompany - Request BaseDn=%s", r.BaseObject())

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "organizationalUnit")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func findBaseDN(node *gabs.Container, rdns []string) (*gabs.Container) {

	if len(rdns) > 0 {
		rdn := rdns[len(rdns)-1]
	    rdns = rdns[:len(rdns)-1]
        //fmt.Printf("node: %+v, rdn: %v, rdns:%v\n", node, rdn, rdns)
		return findBaseDN(node.Search(rdn), rdns)
	} else {
        //fmt.Printf("Using node: %v\n", node)
		return node
	}

}


func matchesFilterAnd(node *gabs.Container, f message.FilterAnd) (bool) {
	//log.Printf("& filter %+v", f)
	for _, filter := range f {
		if !matches(node, filter) {
			return false
		}
	}
	return true
}
func matchesFilterOr(node *gabs.Container, f message.FilterOr) (bool) {
	//log.Printf("| filter %+v", f)
	for _, filter := range f {
		if matches(node, filter) {
			return true
		}
	}
	return false
}
func matchesFilterNot(node *gabs.Container, f message.FilterNot) (bool) {
	log.Printf("! filter %+v", f)
	return false
}
func matchesFilterEqualityMatch(node *gabs.Container, f message.FilterEqualityMatch) (bool) {
	if node.Search(strings.ToLower(string(f.AttributeDesc()))).Data() == string(f.AssertionValue()) {
		log.Printf("= filter %+v matches %+v", f, node)
		return true
	}
	//log.Printf("= filter %+v does not match %+v", f, node)
	return false
}
func matchesFilterGreaterOrEqual(node *gabs.Container, f message.FilterGreaterOrEqual) (bool) {
	log.Printf(">= filter %+v", f)
	return false
}
func matchesFilterLessOrEqual(node *gabs.Container, f message.FilterLessOrEqual) (bool) {
	log.Printf("<= filter %+v", f)
	return false
}
func matchesFilterPresent(node *gabs.Container, f message.FilterPresent) (bool) {
	if node.Search(strings.ToLower(string(f))) != nil {
		log.Printf("* filter %+v matches %+v", f, node)
		return true
	}
	log.Printf("* filter %+v does not match %+v", f, node)
	return false
}
func matchesFilterApproxMatch(node *gabs.Container, f message.FilterApproxMatch) (bool) {
	log.Printf("~ filter %+v", f)
	return false
}
func matchesFilterSubstrings(node *gabs.Container, f message.FilterSubstrings) (bool) {
	filters := "S"
	search := "^"
		for _, fs := range f.Substrings() {
			switch fsv := fs.(type) {
			case message.SubstringInitial:
				filters += "I"
				search += string(fsv) + "*"
			case message.SubstringAny:
				filters += "A"
				search += "*" + string(fsv) + "*"
			case message.SubstringFinal:
				filters += "F"
				search += "*" + string(fsv)
			}
		}
	search += "$"
	search = strings.Replace(strings.Replace(search, "**", "*", -1), "*", ".*", -1)
	re := regexp.MustCompile(search)
	if re.MatchString(node.Search(strings.ToLower(string(f.Type_()))).Data().(string)) {
		log.Printf("%s filter %+v matches %+v (regex=%s)", filters, f, node, search)
		return true
	}
	return false
}
func matchesFilterFilterExtensibleMatch(node *gabs.Container, f message.FilterExtensibleMatch) (bool) {
	log.Printf("E filter %+v", f)
	return false
}

func matches(node *gabs.Container, f message.Filter) (bool) {
	switch f := f.(type) {
	case message.FilterAnd:				return matchesFilterAnd(node, f)
	case message.FilterOr:				return matchesFilterOr(node, f)
	case message.FilterNot:				return matchesFilterNot(node, f)
	case message.FilterEqualityMatch:	return matchesFilterEqualityMatch(node, f)
	case message.FilterGreaterOrEqual:	return matchesFilterGreaterOrEqual(node, f)
	case message.FilterLessOrEqual:		return matchesFilterLessOrEqual(node, f)
	case message.FilterPresent:			return matchesFilterPresent(node, f)
	case message.FilterApproxMatch:		return matchesFilterApproxMatch(node, f)
	case message.FilterSubstrings:		return matchesFilterSubstrings(node, f)
	case message.FilterExtensibleMatch:	return matchesFilterFilterExtensibleMatch(node, f)
	default:
		log.Printf("Unknown filter %+v", f)
	}
	return false
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	//baseDN := findBaseDN(jsonParsed, rdns)
	//log.Printf("BaseDn=%s", baseDN)

	children, _ := jsonParsed.ChildrenMap()
	for key, child := range children {
		if strings.HasSuffix(key, string(r.BaseObject())) {
			fmt.Printf("checking node: %v\n", key)
			if (matches(child, r.Filter())) {
				fmt.Printf("found match %v\n", child)
				e := ldap.NewSearchResultEntry(key)
				for _, attribute := range r.Attributes() {
					if attribute == "dn" {
						continue
					}
					value := child.Search(string(attribute))
					fmt.Printf("checking attribute: %+v for value: %+v\n", attribute, value)
					if (value != nil) {
						log.Printf("Adding Attribute %s with value %s", string(attribute), value)
						e.AddAttribute(message.AttributeDescription(string(attribute)), message.AttributeValue(value.Data().(string)))
					}
				}
				w.Write(e)
			}
		} else {
			fmt.Printf("node: %v not in basedn %v\n", key, r.BaseObject())
		}
	}


/*
	e := ldap.NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "inetOrgPerson")
	e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
	e.AddAttribute("company", "SODADI")
	e.AddAttribute("department", "DSI/SEC")
	e.AddAttribute("l", "Ferrieres en brie")
	e.AddAttribute("mobile", "0612324567")
	e.AddAttribute("telephoneNumber", "0612324567")
	e.AddAttribute("cn", "Valère JEANTET")
	e.AddAttribute("entryUUID", "2d6391b7-76c2-4584-a61e-7c09003fc709")
	w.Write(e)

	e = ldap.NewSearchResultEntry("cn=Claire Thomas, " + string(r.BaseObject()))
	e.AddAttribute("objectClass", "top", "inetOrgPerson")
	e.AddAttribute("mail", "claire.thomas@gmail.com")
	e.AddAttribute("cn", "Claire THOMAS")
	e.AddAttribute("entryUUID", "fba205d9-e8bc-4b47-a84b-3702eee89c6f")
	w.Write(e)
*/
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}


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

	routes.Search(handleSearchDSE).
		BaseDn("").
		Scope(ldap.SearchRequestScopeBaseObject).
		Filter("(objectclass=*)").
		Label("Search - ROOT DSE")

	routes.Search(handleSearchMyCompany).
		BaseDn("o=My Company, c=US").
		Scope(ldap.SearchRequestScopeBaseObject).
		Label("Search - Compagny Root")

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