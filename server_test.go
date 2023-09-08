package ldap

import (
	"bytes"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var listenString = "localhost:3389"
var ldapURL = "ldap://" + listenString
var timeout = 400 * time.Millisecond
var serverBaseDN = "o=testers,c=test"

/////////////////////////
func TestBindAnonOK(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindAnonFail(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindSimpleOK(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", bindSimple{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", bindSimple{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindSSL(t *testing.T) {
	ldapURLSSL := "ldaps://" + listenString
	longerTimeout := 300 * time.Millisecond
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	go func() {
		if err := s.ListenAndServeTLS(listenString, "tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem"); err != nil {
			t.Errorf("s.ListenAndServeTLS failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		cmd.Env = []string{"LDAPTLS_REQCERT=ALLOW"}
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 2):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
func TestBindPanic(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	s.BindFunc("", bindPanic{})
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	s.Close()
}

/////////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	done := make(chan bool)
	s := NewServer()

	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindAnonOK{})
	s.SetStats(true)
	go func() {
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
	s.Close()
}

/////////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct {
}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindPanic struct {
}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	panic("test panic at the disco")
	return LDAPResultInvalidCredentials, nil
}

type bindCaseInsensitive struct {
}

func (b bindCaseInsensitive) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if strings.ToLower(bindDN) == "cn=case,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type searchSimple struct {
}

func (s searchSimple) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=ned,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"ned"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"ned"}},
			&EntryAttribute{"description", []string{"ned via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=trent,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"trent"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5005"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"trent"}},
			&EntryAttribute{"description", []string{"trent via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=randy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"randy"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5555"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"randy"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct {
}

func (s searchSimple2) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}},
			&EntryAttribute{"o", []string{"testers"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"hamburger"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchPanic struct {
}

func (s searchPanic) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	panic("this is a test panic")
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchControls struct {
}

func (s searchControls) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}},
			&EntryAttribute{"o", []string{"testers"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"hamburger"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchCaseInsensitive struct {
}

func (s searchCaseInsensitive) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=CASE,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"CaSe"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5005"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"trent"}},
			&EntryAttribute{"description", []string{"trent via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

func TestRouteFunc(t *testing.T) {
	cases := []struct {
		key      string
		expected string
		values   []string
	}{
		{values: []string{"a=b", "x=y,a=b", "tt"}, key: "", expected: ""},
		{values: []string{"a=b", "x=y,a=b", "tt"}, key: "a=b", expected: "a=b"},
		{values: []string{"aa=b", "x=y,aa=b", "tt"}, key: "a=b", expected: ""},
		{values: []string{"x=y,a=b", "a=b", "tt"}, key: "x=y,a=b", expected: "x=y,a=b"},
		{values: []string{"x=y,a=b", "a=b", "tt"}, key: "nosuch", expected: ""},
	}

	for _, c := range cases {
		res := routeFunc(c.key, c.values)
		if res != c.expected {
			t.Errorf("routeFunc failed: (%v , %v) -> %v != %v", c.key, c.values, c.expected, res)
		}
	}
}
