package ldap

import (
	"fmt"
	"testing"
)

func setupSuite(t *testing.T) func() {
	s := NewServer()
	s.EnforceLDAP = true
	r := NewRouter()
	r.HandleBind(bindAnonOK{})
	s.Handler(r)
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()
	s.waitForReady()
	// Return a function to teardown the test
	return func() {
		s.Close()
	}
}

var baseDN = "dc=umich,dc=edu"
var filter = []string{
	"(cn=cis-fac)",
	"(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
	"(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))"}
var attributes = []string{
	"cn",
	"description"}

func TestClose(t *testing.T) {
	defer setupSuite(t)()
	fmt.Printf("TestConnect: starting...\n")
	l, err := Dial("tcp", listenString)
	if err != nil {
		t.Errorf(err.Error())
	}
	l.Close()
	l.Close()
}

func TestConnect(t *testing.T) {
	defer setupSuite(t)()
	fmt.Printf("TestConnect: starting...\n")
	l, err := Dial("tcp", listenString)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()
	fmt.Printf("TestConnect: finished...\n")
}

func TestSearch(t *testing.T) {
	defer setupSuite(t)()
	fmt.Printf("TestSearch: starting...\n")
	l, err := Dial("tcp", listenString)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Printf("TestSearch: %s -> num of entries = %d\n", searchRequest.Filter, len(sr.Entries))
}

func TestSearchWithPaging(t *testing.T) {
	defer setupSuite(t)()
	fmt.Printf("TestSearchWithPaging: starting...\n")
	l, err := Dial("tcp", listenString)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind("", "")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[1],
		attributes,
		nil)
	sr, err := l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Printf("TestSearchWithPaging: %s -> num of entries = %d\n", searchRequest.Filter, len(sr.Entries))
}

func testMultiGoroutineSearch(t *testing.T, l *Conn, results chan *SearchResult, i int) {
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[i],
		attributes,
		nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Errorf(err.Error())
		results <- nil
		return
	}
	results <- sr
}

func TestMultiGoroutineSearch(t *testing.T) {
	defer setupSuite(t)()
	fmt.Printf("TestMultiGoroutineSearch: starting...\n")
	l, err := Dial("tcp", listenString)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	results := make([]chan *SearchResult, len(filter))
	for i := range filter {
		results[i] = make(chan *SearchResult)
		go testMultiGoroutineSearch(t, l, results[i], i)
	}
	for i := range filter {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", filter[i])
		} else {
			fmt.Printf("TestMultiGoroutineSearch(%d): %s -> num of entries = %d\n", i, filter[i], len(sr.Entries))
		}
	}
}
