package ldap

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"go.opentelemetry.io/otel"
)

//
type Server struct {
	handler     Handler
	Quit        chan bool
	EnforceLDAP bool
	Stats       *Stats
}

type Session struct {
	boundDN string
	conn    net.Conn
	server  *Server
	handler Handler
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

	s.handler = NewRouter()
	s.Stats = nil
	return s
}

func (server *Server) Handler(h Handler) {
	server.handler = h
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
	defer close(server.Quit)

	conChan := make(chan net.Conn)
	errChan := make(chan error)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errChan <- err
				return
			}
			conChan <- conn
		}
	}()

	ctx, span := otel.Tracer("LDAP").Start(context.Background(), "Listen")
	defer span.End()

	for {
		select {
		case c := <-conChan:
			go server.handleConnection(c, ctx)
		case err := <-errChan:
			return err
		case <-server.Quit:
			ln.Close()
			return nil
		}
	}
}

//Close closes the underlying net.Listener, and waits for confirmation
func (server *Server) Close() {
	server.Quit <- true
	<-server.Quit
}

//
func (server *Server) handleConnection(conn net.Conn, ctx context.Context) {
	ctx, span := otel.Tracer("LDAP").Start(ctx, "Connection")
	defer span.End()

	session := &Session{
		conn:    conn,
		server:  server,
		handler: server.handler,
		boundDN: "",
	}

	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		//start := time.Now()
		if err == io.EOF || err == io.ErrUnexpectedEOF { // Client closed connection
			break
		} else if err != nil {
			log.Printf("handleConnection ber.ReadPacket ERROR: %s", err.Error())
			break
		}
		responsePacket := session.handleCommand(packet, ctx)
		if responsePacket != nil {
			sendPacket(conn, responsePacket)
		}
	}
}

func (session *Session) handleCommand(packet *ber.Packet, ctx context.Context) (p *ber.Packet) {
	ctx, span := otel.Tracer("LDAP").Start(ctx, "Command")
	defer span.End()
	// sanity check this packet
	if len(packet.Children) < 2 {
		return nil
	}

	// check the message ID
	messageID64, ok := packet.Children[0].Value.(int64)
	if !ok {
		return nil
	}
	messageID := uint64(messageID64)

	// check the ClassType
	req := packet.Children[1]
	if req.ClassType != ber.ClassApplication {
		return nil
	}
	// handle controls if present
	controls := []Control{}
	if len(packet.Children) > 2 {
		for _, child := range packet.Children[2].Children {
			controls = append(controls, DecodeControl(child))
		}
	}

	// dispatch the LDAP operation
	switch req.Tag {
	default:
		return encodeLDAPResponse(messageID, ApplicationAddResponse, LDAPResultOperationsError, "Unsupported operation")

	case ApplicationBindRequest:
		ldapResultCode := session.Bind(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationBindResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationSearchRequest:
		code := LDAPResultCode(LDAPResultSuccess)
		if err := session.Search(req, &controls, messageID, session.server, ctx); err != nil {
			log.Printf("handleSearchRequest error %s", err.Error())
			e := err.(*Error)
			code = e.ResultCode
		}
		return encodeLDAPResponse(messageID, ApplicationSearchResultDone, code, LDAPResultCodeMap[code])

	case ApplicationUnbindRequest:
		session.boundDN = "" // anything else?
	case ApplicationExtendedRequest:
		ldapResultCode := session.Extended(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationExtendedResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationAbandonRequest:
		session.Abandon(req, session.handler, ctx)

	case ApplicationAddRequest:
		ldapResultCode := session.Add(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationAddResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationModifyRequest:
		ldapResultCode := session.Modify(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationModifyResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationDelRequest:
		ldapResultCode := session.Delete(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationDelResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationModifyDNRequest:
		ldapResultCode := session.ModifyDN(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationModifyDNResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])

	case ApplicationCompareRequest:
		ldapResultCode := session.Compare(req, session.handler, ctx)
		return encodeLDAPResponse(messageID, ApplicationCompareResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
	}
	return nil
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
