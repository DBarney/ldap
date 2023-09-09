package ldap

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
)

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
type Server struct {
	Binder     Binder
	Searcher   Searcher
	Adder      Adder
	Modifier   Modifier
	Deleter    Deleter
	ModifyDNr  ModifyDNr
	Comparer   Comparer
	Abandoner  Abandoner
	Extendeder Extender
	Unbinder   Unbinder
	Closer     Closer

	Quit        chan bool
	EnforceLDAP bool
	Stats       *Stats
}

type Stats struct {
	Conns      int
	Binds      int
	Unbinds    int
	Searches   int
	statsMutex sync.Mutex
}

type ServerSearchResult struct {
	Entries    []*Entry
	Referrals  []string
	Controls   []Control
	ResultCode LDAPResultCode
}

//
func NewServer() *Server {
	s := new(Server)
	s.Quit = make(chan bool)

	d := defaultHandler{}
	s.BindFunc(d)
	s.SearchFunc(d)
	s.AddFunc(d)
	s.ModifyFunc(d)
	s.DeleteFunc(d)
	s.ModifyDNFunc(d)
	s.CompareFunc(d)
	s.AbandonFunc(d)
	s.ExtendedFunc(d)
	s.UnbindFunc(d)
	s.CloseFunc(d)
	s.Stats = nil
	return s
}
func (server *Server) BindFunc(f Binder) {
	server.Binder = f
}
func (server *Server) SearchFunc(f Searcher) {
	server.Searcher = f
}
func (server *Server) AddFunc(f Adder) {
	server.Adder = f
}
func (server *Server) ModifyFunc(f Modifier) {
	server.Modifier = f
}
func (server *Server) DeleteFunc(f Deleter) {
	server.Deleter = f
}
func (server *Server) ModifyDNFunc(f ModifyDNr) {
	server.ModifyDNr = f
}
func (server *Server) CompareFunc(f Comparer) {
	server.Comparer = f
}
func (server *Server) AbandonFunc(f Abandoner) {
	server.Abandoner = f
}
func (server *Server) ExtendedFunc(f Extender) {
	server.Extendeder = f
}
func (server *Server) UnbindFunc(f Unbinder) {
	server.Unbinder = f
}
func (server *Server) CloseFunc(f Closer) {
	server.Closer = f
}
func (server *Server) QuitChannel(quit chan bool) {
	server.Quit = quit
}

func (server *Server) ListenAndServeTLS(listenString string, certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.ServerName = "localhost"
	ln, err := tls.Listen("tcp", listenString, &tlsConfig)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}

func (server *Server) SetStats(enable bool) {
	if enable {
		server.Stats = &Stats{}
	} else {
		server.Stats = nil
	}
}

func (server *Server) GetStats() Stats {
	defer func() {
		server.Stats.statsMutex.Unlock()
	}()
	server.Stats.statsMutex.Lock()
	return *server.Stats
}

func (server *Server) ListenAndServe(listenString string) error {
	ln, err := net.Listen("tcp", listenString)
	if err != nil {
		return err
	}
	return server.Serve(ln)
}

func (server *Server) Serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					log.Printf("Error accepting network connection: %s", err.Error())
				}
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.Stats.countConns(1)
			go server.handleConnection(c)
		case <-server.Quit:
			ln.Close()
			close(server.Quit)
			break listener
		}
	}
	return nil
}

//Close closes the underlying net.Listener, and waits for confirmation
func (server *Server) Close() {
	server.Quit <- true
	<-server.Quit
}

//
func (server *Server) handleConnection(conn net.Conn) {
	boundDN := "" // "" == anonymous

	defer conn.Close()
	defer server.Closer.Close(boundDN, conn)

	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF || err == io.ErrUnexpectedEOF { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			return
		}

		// check the message ID
		messageID64, ok := packet.Children[0].Value.(int64)
		if !ok {
			return
		}
		messageID := uint64(messageID64)

		// check the ClassType
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			return
		}
		// handle controls if present
		controls := []Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				controls = append(controls, DecodeControl(child))
			}
		}

		//log.Printf("DEBUG: handling operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
		//ber.PrintPacket(packet) // DEBUG

		// dispatch the LDAP operation
		var responsePacket *ber.Packet
		switch req.Tag { // ldap op code
		default:
			log.Printf("Unhandled operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
			responsePacket = encodeLDAPResponse(messageID, ApplicationAddResponse, LDAPResultOperationsError, "Unsupported operation")

		case ApplicationBindRequest:
			server.Stats.countBinds(1)
			ldapResultCode := HandleBindRequest(req, server.Binder, conn)
			if ldapResultCode == LDAPResultSuccess {
				// no check needed, as HandleBindRequest does the check already
				boundDN = req.Children[1].Value.(string)
			}
			responsePacket = encodeBindResponse(messageID, ldapResultCode)
		case ApplicationSearchRequest:
			server.Stats.countSearches(1)
			if err := HandleSearchRequest(req, &controls, messageID, boundDN, server, conn); err != nil {
				log.Printf("handleSearchRequest error %s", err.Error()) // TODO: make this more testable/better err handling - stop using log, stop using breaks?
				e := err.(*Error)
				responsePacket = encodeSearchDone(messageID, e.ResultCode)
			} else {
				responsePacket = encodeSearchDone(messageID, LDAPResultSuccess)
			}
		case ApplicationUnbindRequest:
			server.Stats.countUnbinds(1)
			continue
		case ApplicationExtendedRequest:
			ldapResultCode := HandleExtendedRequest(req, boundDN, server.Extendeder, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationExtendedResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		case ApplicationAbandonRequest:
			HandleAbandonRequest(req, boundDN, server.Abandoner, conn)
			continue

		case ApplicationAddRequest:
			ldapResultCode := HandleAddRequest(req, boundDN, server.Adder, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationAddResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		case ApplicationModifyRequest:
			ldapResultCode := HandleModifyRequest(req, boundDN, server.Modifier, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationModifyResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		case ApplicationDelRequest:
			ldapResultCode := HandleDeleteRequest(req, boundDN, server.Deleter, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationDelResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		case ApplicationModifyDNRequest:
			ldapResultCode := HandleModifyDNRequest(req, boundDN, server.ModifyDNr, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationModifyDNResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		case ApplicationCompareRequest:
			ldapResultCode := HandleCompareRequest(req, boundDN, server.Comparer, conn)
			responsePacket = encodeLDAPResponse(messageID, ApplicationCompareResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
		}
		sendPacket(conn, responsePacket)
	}

}

//
func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())
		return err
	}
	return nil
}

//
func encodeLDAPResponse(messageID uint64, responseType uint8, ldapResultCode LDAPResultCode, message string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	reponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(responseType), nil, ApplicationMap[ber.Tag(responseType)])
	reponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "errorMessage: "))
	responsePacket.AppendChild(reponse)
	return responsePacket
}

//
type defaultHandler struct {
}

func (h defaultHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInvalidCredentials, nil
}
func (h defaultHandler) Search(boundDN string, req SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}, nil
}
func (h defaultHandler) Add(boundDN string, req AddRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Modify(boundDN string, req ModifyRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Delete(boundDN, deleteDN string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) ModifyDN(boundDN string, req ModifyDNRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Abandon(boundDN string, conn net.Conn) error {
	return nil
}
func (h defaultHandler) Extended(boundDN string, req ExtendedRequest, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultProtocolError, nil
}
func (h defaultHandler) Unbind(boundDN string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultSuccess, nil
}
func (h defaultHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close()
	return nil
}

//
func (stats *Stats) countConns(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Conns += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countBinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Binds += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countUnbinds(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Unbinds += delta
		stats.statsMutex.Unlock()
	}
}
func (stats *Stats) countSearches(delta int) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Searches += delta
		stats.statsMutex.Unlock()
	}
}

//
