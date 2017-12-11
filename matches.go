package main

import (
	"log"
	"regexp"
	"strings"

	"github.com/Jeffail/gabs"
	"github.com/vjeantet/goldap/message"
)

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
	n := node.Search(strings.ToLower(string(f.AttributeDesc())))
	children, err := n.Children()
	if err != nil {
		if n.Data() == string(f.AssertionValue()) {
			log.Printf("= filter %+v matches %+v value %+v", f, node, n)
			return true
		}
	} else {
		for _, value := range children {
			if value.Data() == string(f.AssertionValue()) {
				log.Printf("= filter %+v matches %+v value %+v in %+v", f, node, value, children)
				return true
			}
		}
	}
	log.Printf("= filter %+v does not match %+v values %+v", f, node, n)
	return false
}
func matchesFilterGreaterOrEqual(node *gabs.Container, f message.FilterGreaterOrEqual) (bool) {
	log.Printf(">= filter %+v NEEDS IMPLEMENTING", f) // TODO not yet implemented
	return false
}
func matchesFilterLessOrEqual(node *gabs.Container, f message.FilterLessOrEqual) (bool) {
	log.Printf("<= filter %+v NEEDS IMPLEMENTING", f) // TODO not yet implemented
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
	log.Printf("~ filter %+v NEEDS IMPLEMENTING", f) // TODO not yet implemented
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
	value := node.Search(strings.ToLower(string(f.Type_()))).Data()
	log.Printf("%s filter %+v checking %+v with value %+v (regex=%s)", filters, f, node, value, search)
	re := regexp.MustCompile(search)

	if value != nil && re.MatchString(value.(string)) {
		log.Printf("matches")
		return true
	}
	log.Printf("does not match")
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