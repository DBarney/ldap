package ldap

import (
	"net"
)

type Handler interface {
	Binder
	Searcher
	Adder
	Modifier
	Deleter
	ModifyDNr
	Comparer
	Abandoner
	Extender
	Unbinder
	Closer
}

//
type Binder interface {
	Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error)
}
type Searcher interface {
	Search(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error)
}
type Adder interface {
	Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error)
}
type Modifier interface {
	Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error)
}
type Deleter interface {
	Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error)
}
type ModifyDNr interface {
	ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error)
}
type Comparer interface {
	Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error)
}
type Abandoner interface {
	Abandon(boundDN string, conn net.Conn) error
}
type Extender interface {
	Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error)
}
type Unbinder interface {
	Unbind(boundDN string, conn net.Conn) (LDAPResultCode, error)
}
type Closer interface {
	Close(boundDN string, conn net.Conn) error
}

//
type Router struct {
	bind     func(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error)
	search   func(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error)
	add      func(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error)
	modify   func(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error)
	_delete  func(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error)
	modifyDN func(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error)
	compare  func(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error)
	abandon  func(boundDN string, conn net.Conn) error
	extend   func(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error)
	unbind   func(boundDN string, conn net.Conn) (LDAPResultCode, error)
	_close   func(boundDN string, conn net.Conn) error
}

func NewRouter() *Router {
	d := &Router{}
	return d
}

func (r *Router) HandleBind(b Binder) {
	r.bind = b.Bind
}
func (r *Router) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if r.bind != nil {
		return r.bind(bindDN, bindSimplePw, conn)
	}
	return LDAPResultInvalidCredentials, nil
}

func (r *Router) HandleSearch(s Searcher) {
	r.search = s.Search
}
func (r *Router) Search(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	if r.search != nil {
		return r.search(boundDN, req, conn)
	}
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}, nil
}

func (r *Router) HandleAdd(a Adder) {
	r.add = a.Add
}
func (r *Router) Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error) {
	if r.add != nil {
		return r.add(boundDN, req, conn)
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (r *Router) HandleModify(m Modifier) {
	r.modify = m.Modify
}
func (r *Router) Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error) {
	if r.modify != nil {
		return r.modify(boundDN, req, conn)
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (r *Router) HandleDelete(d Deleter) {
	r._delete = d.Delete
}
func (r *Router) Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error) {
	if r._delete != nil {
		return r._delete(boundDN, deleteDN, conn)
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (r *Router) HandleModifyDN(m ModifyDNr) {
	r.modifyDN = m.ModifyDN
}
func (r *Router) ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error) {
	if r.modifyDN != nil {
		return r.modifyDN(boundDN, req, conn)
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (r *Router) HandleCompare(c Comparer) {
	r.compare = c.Compare
}
func (r *Router) Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error) {
	if r.compare != nil {
		return r.compare(boundDN, req, conn)
	}
	return LDAPResultInsufficientAccessRights, nil
}

func (r *Router) HandleAbandon(a Abandoner) {
	r.abandon = a.Abandon
}
func (r *Router) Abandon(boundDN string, conn net.Conn) error {
	if r.abandon != nil {
		return r.abandon(boundDN, conn)
	}
	return nil
}

func (r *Router) HandleExtend(e Extender) {
	r.extend = e.Extended
}
func (r *Router) Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error) {
	if r.extend != nil {
		return r.extend(boundDN, req, conn)
	}
	return LDAPResultProtocolError, nil
}

func (r *Router) HandleUnbind(u Unbinder) {
	r.unbind = u.Unbind
}
func (r *Router) Unbind(boundDN string, conn net.Conn) (LDAPResultCode, error) {
	if r.unbind != nil {
		return r.unbind(boundDN, conn)
	}
	return LDAPResultSuccess, nil
}

func (r *Router) HandleClose(c Closer) {
	r._close = c.Close
}
func (r *Router) Close(boundDN string, conn net.Conn) error {
	if r._close != nil {
		return r._close(boundDN, conn)
	}
	conn.Close()
	return nil
}
