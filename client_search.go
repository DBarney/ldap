package ldap

import (
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
)

var ScopeMap = map[int]string{
	ScopeBaseObject:   "Base Object",
	ScopeSingleLevel:  "Single Level",
	ScopeWholeSubtree: "Whole Subtree",
}

const (
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3
)

var DerefMap = map[int]string{
	NeverDerefAliases:   "NeverDerefAliases",
	DerefInSearching:    "DerefInSearching",
	DerefFindingBaseObj: "DerefFindingBaseObj",
	DerefAlways:         "DerefAlways",
}

type Entry struct {
	DN         string
	Attributes []*EntryAttribute
}

func (e *Entry) GetAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

func (e *Entry) GetAttributeValue(attribute string) string {
	values := e.GetAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (e *Entry) Print() {
	fmt.Printf("DN: %s\n", e.DN)
	for _, attr := range e.Attributes {
		attr.Print()
	}
}

func (e *Entry) PrettyPrint(indent int) {
	fmt.Printf("%sDN: %s\n", strings.Repeat(" ", indent), e.DN)
	for _, attr := range e.Attributes {
		attr.PrettyPrint(indent + 2)
	}
}

type EntryAttribute struct {
	Name   string
	Values []string
}

func (e *EntryAttribute) Print() {
	fmt.Printf("%s: %s\n", e.Name, e.Values)
}

func (e *EntryAttribute) PrettyPrint(indent int) {
	fmt.Printf("%s%s: %s\n", strings.Repeat(" ", indent), e.Name, e.Values)
}

type SearchResult struct {
	Entries   []*Entry
	Referrals []string
	Controls  []Control
}

func (s *SearchResult) Print() {
	for _, entry := range s.Entries {
		entry.Print()
	}
}

func (s *SearchResult) PrettyPrint(indent int) {
	for _, entry := range s.Entries {
		entry.PrettyPrint(indent)
	}
}

func NewSearchRequest(
	BaseDN string,
	Scope, DerefAliases, SizeLimit, TimeLimit int,
	TypesOnly bool,
	Filter string,
	Attributes []string,
	Controls []Control,
) *SearchRequest {
	return &SearchRequest{
		BaseDN:       BaseDN,
		Scope:        Scope,
		DerefAliases: DerefAliases,
		SizeLimit:    SizeLimit,
		TimeLimit:    TimeLimit,
		TypesOnly:    TypesOnly,
		Filter:       Filter,
		Attributes:   Attributes,
		Controls:     Controls,
	}
}

func (l *Conn) SearchWithPaging(searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error) {
	if searchRequest.Controls == nil {
		searchRequest.Controls = make([]Control, 0)
	}

	pagingControl := NewControlPaging(pagingSize)
	searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	searchResult := new(SearchResult)
	for {
		result, err := l.Search(searchRequest)
		l.Debug.Printf("Looking for Paging Control...")
		if err != nil {
			return searchResult, err
		}
		if result == nil {
			return searchResult, NewError(ErrorNetwork, errors.New("ldap: packet not received"))
		}

		for _, entry := range result.Entries {
			searchResult.Entries = append(searchResult.Entries, entry)
		}
		for _, referral := range result.Referrals {
			searchResult.Referrals = append(searchResult.Referrals, referral)
		}
		for _, control := range result.Controls {
			searchResult.Controls = append(searchResult.Controls, control)
		}

		l.Debug.Printf("Looking for Paging Control...")
		pagingResult := FindControl(result.Controls, ControlTypePaging)
		if pagingResult == nil {
			pagingControl = nil
			l.Debug.Printf("Could not find paging control.  Breaking...")
			break
		}

		cookie := pagingResult.(*ControlPaging).Cookie
		if len(cookie) == 0 {
			pagingControl = nil
			l.Debug.Printf("Could not find cookie.  Breaking...")
			break
		}
		pagingControl.SetCookie(cookie)
	}

	if pagingControl != nil {
		l.Debug.Printf("Abandoning Paging...")
		pagingControl.PagingSize = 0
		l.Search(searchRequest)
	}

	return searchResult, nil
}

func (l *Conn) Search(searchRequest *SearchRequest) (*SearchResult, error) {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	// encode search request
	encodedSearchRequest := searchRequest.ToBER()
	packet.AppendChild(encodedSearchRequest)
	// encode search controls
	if searchRequest.Controls != nil {
		packet.AppendChild(encodeControls(searchRequest.Controls))
	}

	l.Debug.PrintPacket(packet)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	if channel == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	result := &SearchResult{
		Entries:   make([]*Entry, 0),
		Referrals: make([]string, 0),
		Controls:  make([]Control, 0)}

	foundSearchResultDone := false
	for !foundSearchResultDone {
		l.Debug.Printf("%d: waiting for response", messageID)
		packet = <-channel
		l.Debug.Printf("%d: got response %p", messageID, packet)
		if packet == nil {
			return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
		}

		if l.Debug {
			if err := addLDAPDescriptions(packet); err != nil {
				return nil, err
			}
			ber.PrintPacket(packet)
		}

		switch packet.Children[1].Tag {
		case 4:
			entry := new(Entry)
			entry.DN = packet.Children[1].Children[0].Value.(string)
			for _, child := range packet.Children[1].Children[1].Children {
				attr := new(EntryAttribute)
				attr.Name = child.Children[0].Value.(string)
				for _, value := range child.Children[1].Children {
					attr.Values = append(attr.Values, value.Value.(string))
				}
				entry.Attributes = append(entry.Attributes, attr)
			}
			result.Entries = append(result.Entries, entry)
		case 5:
			resultCode, resultDescription := getLDAPResultCode(packet)
			if resultCode != 0 {
				return result, NewError(resultCode, errors.New(resultDescription))
			}
			if len(packet.Children) == 3 {
				for _, child := range packet.Children[2].Children {
					result.Controls = append(result.Controls, DecodeControl(child))
				}
			}
			foundSearchResultDone = true
		case 19:
			result.Referrals = append(result.Referrals, packet.Children[1].Children[0].Value.(string))
		}
	}
	l.Debug.Printf("%d: returning", messageID)
	return result, nil
}
