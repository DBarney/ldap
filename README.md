[![GoDoc](https://godoc.org/gopkg.in/ldap.v2?status.svg)](https://godoc.org/gopkg.in/ldap.v2)
[![Build Status](https://travis-ci.org/go-ldap/ldap.svg)](https://travis-ci.org/go-ldap/ldap)

# Basic LDAP v3 functionality for the GO programming language.

## Install

For the latest version use:

    go get gopkg.in/ldap.v2

Import the latest version with:

    import "gopkg.in/ldap.v2"

## Required Libraries:

 - gopkg.in/asn1-ber.v1

## Features:

 - Connecting to LDAP server (non-TLS, TLS, STARTTLS)
 - Binding to LDAP server
 - Searching for entries
 - Filter Compile / Decompile
 - Paging Search Results
 - Modify Requests / Responses
 - Add Requests / Responses
 - Delete Requests / Responses

## Examples:

 - search
 - modify

## Contributing:

Bug reports and pull requests are welcome!

Before submitting a pull request, please make sure tests and verification scripts pass:
```
make all
```

To set up a pre-push hook to run the tests and verify scripts before pushing:
```
ln -s ../../.githooks/pre-push .git/hooks/pre-push
```


---

The **server** portion implements Bind and Search from [RFC4510](http://tools.ietf.org/html/rfc4510), has good testing coverage, and is compatible with any LDAPv3 client.  It provides the building blocks for a custom LDAP server, but you must implement the backend datastore of your choice.


## LDAP server notes:
The server library is modeled after net/http - you designate handlers for the LDAP operations you want to support (Bind/Search/etc.), then start the server with ListenAndServe().  You can specify different handlers for different baseDNs - they must implement the interfaces of the operations you want to support:
```go
type Binder interface {
    Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error)
}
type Searcher interface {
    Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error)
}
type Closer interface {
    Close(conn net.Conn) error
}
```

### A basic bind-only LDAP server
```go
func main() {
  s := ldap.NewServer()
  handler := ldapHandler{}
  s.BindFunc("", handler)
  if err := s.ListenAndServe("localhost:389"); err != nil {
    log.Fatal("LDAP Server Failed: %s", err.Error())
  }
}
type ldapHandler struct {
}
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}
```

* Server.EnforceLDAP: Normally, the LDAP server will return whatever results your handler provides.  Set the **Server.EnforceLDAP** flag to **true** and the server will apply the LDAP **search filter**, **attributes limits**, **size/time limits**, **search scope**, and **base DN matching** to your handler's dataset.  This makes it a lot simpler to write a custom LDAP server without worrying about LDAP internals.

### LDAP server examples:
* examples/server.go: **Basic LDAP authentication (bind and search only)**
* examples/proxy.go: **Simple LDAP proxy server.**
* server_test: **The tests have examples of all server functions.**

*Warning: Do not use the example SSL certificates in production!*

### Known limitations:

* Golang's TLS implementation does not support SSLv2.  Some old OSs require SSLv2, and are not able to connect to an LDAP server created with this library's ListenAndServeTLS() function.  If you *must* support legacy (read: *insecure*) SSLv2 clients, run your LDAP server behind HAProxy.

### Not implemented:
All of [RFC4510](http://tools.ietf.org/html/rfc4510) is implemented **except**:
* 4.1.11.  Controls
* 4.5.1.3.  SearchRequest.derefAliases
* 4.5.1.5.  SearchRequest.timeLimit
* 4.5.1.6.  SearchRequest.typesOnly

*Server library by: [nmcclain](https://github.com/nmcclain)*

---
The Go gopher was designed by Renee French. (http://reneefrench.blogspot.com/)
The design is licensed under the Creative Commons 3.0 Attributions license.
Read this article for more details: http://blog.golang.org/gopher
