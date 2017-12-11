package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	ldap "github.com/vjeantet/ldapserver"
	"github.com/vjeantet/goldap/message"
)


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

type SearchControlValue struct {
	Size	int
	Cookie	string
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())
	log.Printf("Request Controls=%+v", m.Controls())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	for _, control := range *m.Controls() {
		if control.ControlType() == "1.2.840.113556.1.4.319" {
			var controlValue SearchControlValue
			/*rest, err := */asn1.Unmarshal(control.ControlValue().Bytes(), &controlValue)
			log.Printf("Paged search request %+v", controlValue)
			// TODO implement paged search
		}
	}

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

						stringValue := value.Data().(string);
						if (strings.HasPrefix(stringValue, "{hex}")) {
							bytes, err :=  hex.DecodeString(stringValue[5:])
							if err != nil {
								log.Printf("could not decode hex string %s to bytes", stringValue)
							}
							e.AddAttribute(message.AttributeDescription(string(attribute)), message.AttributeValue(bytes))
						} else {
							e.AddAttribute(message.AttributeDescription(string(attribute)), message.AttributeValue(stringValue))
						}
					}
				}
				w.Write(e)
			}
		} else {
			fmt.Printf("node: %v not in basedn %v\n", key, r.BaseObject())
		}
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}
