package raksh

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/oxtoacart/bpool"
	"github.com/pborman/uuid"
	_ "net/http/pprof"
	"strconv"
)

// A StreamingTransport must be safe for concurrent use by multiple
// goroutines.
type StreamingTransport interface {
	// A StreamingTransport provides support to stream HTTP requests
	// and responses to a server, optionally re-using connections
	// to ship multiple http transactions
	//
	// It should not attempt to intrepret the response or modify the
	// request.
	// The Request's URL and Header fields are expected to be initialized
	GetConnection(req *http.Request) (*PersistConn, error)
	PutConnection(pconn *PersistConn) error

	WriteHeader(pconn *PersistConn, req *http.Request) error
	Write(pconn *PersistConn, req *http.Request, src []byte) (int, error)

	ReadResponse(pconn *PersistConn, req *http.Request) (resp *http.Response, err error)
	ClientClose(remote string)
}

type HttpFlow struct {
	Id                string
	Request           *http.Request
	Response          *http.Response
	RequestStreaming  bool
	ResponseStreaming bool
}

func Uuid() string {
	return uuid.New()
}

// HTTP proxy application
// This interface encapsulates the methods that the HTTP
// processing application needs to implement to
// use the mitm proxy service
// - a handler to process HTTP Requests
// - a handler to process HTTP Responses
type HttpApplication interface {
	RequestDataHandler(flow *HttpFlow, data []byte) ([]byte, error)
	ResponseDataHandler(flow *HttpFlow, data []byte) ([]byte, error)
	RequestHandler(flow *HttpFlow) error
	ResponseHandler(flow *HttpFlow) error
	StreamedRequestDataHandler(flow *HttpFlow, buf []byte, last_chunk bool) ([]byte, error)
	StreamedResponseDataHandler(flow *HttpFlow, buf []byte, last_chunk bool) ([]byte, error)
	FailureHandler(flow *HttpFlow)
}

const (
	bufPoolCapacity = 20
)

var defaultTransport = &ProxyTransport{}

// ErrResponseShortWrite means that a write accepted fewer bytes than requested
// but failed to return an explicit error.
var ErrResponseShortWrite = errors.New("Response Short Write")
var ErrRequestShortWrite = errors.New("Request Short Write")

/*
 * Errors that the HttpApplication handlers return on failure.
 * This would then result in appropriate Http Response being
 * sent to the client
 */
var ErrHttpForbiddenRequest = errors.New("Forbidden")
var ErrHttpBadRequest = errors.New("Bad Request")
var ErrHttpUnauthorized = errors.New("Unauthorized")

/*
 *  HTTP mitm proxy
 */
type HttpMitmProxy struct {
	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used
	Transport StreamingTransport

	// BufferPool specifies a buffer pool to get byte slices for use by
	// io.CopyBuffer when copying HTTP request and response bodies
	BufferPool *bpool.BytePool

	// The application that is processes the HTTP data as it is
	// streamed to/from the server being proxied
	app HttpApplication

	// The address at which the proxy listens for new connections
	addr      string
	ChunkSize int64
	certFile  string
	keyFile   string
}

func GetDefaultTransport() *ProxyTransport {
	return defaultTransport
}

func NewHttpMitmProxy(addr string, app HttpApplication, sslCertFile, sslKeyFile string) (*HttpMitmProxy, error) {

	bufferSize := int(chunkSize)
	pool := bpool.NewBytePool(bufPoolCapacity, bufferSize)

	return &HttpMitmProxy{
		addr:       addr,
		Transport:  defaultTransport,
		BufferPool: pool,
		app:        app,
		ChunkSize:  128 * 1024,
		certFile:   sslCertFile,
		keyFile:    sslKeyFile,
	}, nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// FIXME:
// Debugging memory and cpu usage
func initProfiling(port int) {
	addr := ":" + strconv.Itoa(port)
	http.ListenAndServe(addr, http.DefaultServeMux)
}

func (p *HttpMitmProxy) Start() error {

	// start off the profiler
	go initProfiling(6060)

	connStateHandler := func(c net.Conn, state http.ConnState) {
		// we are interested only in closed connections.
		// On a conn close, cleanup the corresponding backend connection
		// to the Server.
		if state == http.StateClosed {
			remote := c.RemoteAddr().String()
			transport := p.Transport

			transport.ClientClose(remote)
		}
	}
	server := &http.Server{
		Addr:      p.addr,
		ConnState: connStateHandler,
		Handler:   p,
	}

	if p.certFile != "" && p.keyFile != "" {
		server.ListenAndServeTLS(p.certFile, p.keyFile)
	} else {
		server.ListenAndServe()
	}
	return nil
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// Checks whether chunked is part of the encodings stack
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

func (p *HttpMitmProxy) streamRequestData(flow *HttpFlow) bool {
	req := flow.Request

	if (req.Method == "PUT" || req.Method == "POST") && req.ContentLength > p.ChunkSize {
		return true
	}
	return false
}

func (p *HttpMitmProxy) streamResponseData(flow *HttpFlow) bool {

	resp := flow.Response
	if flow.Request.Method == "HEAD" {
		return false
	}
	if resp.ContentLength > p.ChunkSize {
		return true
	}
	return false
}

func (p *HttpMitmProxy) processRequest(flow *HttpFlow) error {
	transport := p.Transport

	req := flow.Request
	err := p.app.RequestHandler(flow)
	if err != nil {
		return err
	}

	// get the connection object
	conn, err := transport.GetConnection(req)
	if err != nil {
		return err
	}

	if flow.RequestStreaming == true {
		//now call the app handlers if registered

		err = transport.WriteHeader(conn, req)
		if err != nil {
			return err
		}
		written := int64(0)
		// write the body out, if there is one

		src := req.Body
		reqBytesSeen := int64(0)
		for {
			buf := p.BufferPool.Get()
			nr, err := io.ReadFull(src, buf)
			if nr > 0 {
				reqBytesSeen += int64(nr)
				last_chunk := (reqBytesSeen == req.ContentLength)
				data, err := p.app.StreamedRequestDataHandler(flow, buf[0:nr], last_chunk)
				if err != nil {
					p.BufferPool.Put(buf)
					break
				}
				nr = len(data)
				nw, err := transport.Write(conn, req, data)
				if err != nil {
					p.BufferPool.Put(buf)
					break
				}
				if nw != nr {
					p.BufferPool.Put(buf)
					break
				}
				written += int64(nw)
				if last_chunk {
					p.BufferPool.Put(buf)
					break
				}
			}
			if err == io.EOF {
				p.BufferPool.Put(buf)
				break
			}
			p.BufferPool.Put(buf)
		}
	} else {
		//request body fits in a single buffer block
		if req.ContentLength > 0 {
			buf := p.BufferPool.Get()
			nr, err := io.ReadFull(req.Body, buf)
			if err != io.ErrUnexpectedEOF {
				p.BufferPool.Put(buf)
				return err
			}
			if nr > 0 {
				data, err := p.app.RequestDataHandler(flow, buf[0:nr])
				if err != nil {
					transport.PutConnection(conn)
					return err
				}
				nr = len(data)
				err = transport.WriteHeader(conn, req)
				if err != nil {
					p.BufferPool.Put(buf)
					return err
				}
				nw, err := transport.Write(conn, req, data)
				if err != nil {
					p.BufferPool.Put(buf)
					return err
				}
				if nw != nr {
					err = ErrRequestShortWrite
					p.BufferPool.Put(buf)
					return err
				}
			}
			p.BufferPool.Put(buf)
		} else if chunked(req.TransferEncoding) && req.Body != http.NoBody {
			// aws uses transferEncoding chunked for metadata requests only.
			// these are paged so buffer sizes should be smaller.
			buf, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return err
			}
			data, err := p.app.RequestDataHandler(flow, buf)
			if err != nil {
				transport.PutConnection(conn)
				return err
			}
			nr := len(data)
			err = transport.WriteHeader(conn, req)
			if err != nil {
				return err
			}
			nw, err := transport.Write(conn, req, data)
			if err != nil {
				return err
			}
			if nw != nr {
				err = ErrRequestShortWrite
				return err
			}
		} else {
			_, err := p.app.RequestDataHandler(flow, nil)
			if err != nil {
				transport.PutConnection(conn)
				return err
			}
			err = transport.WriteHeader(conn, req)
			if err != nil {
				return err
			}
		}
	}
	flow.Response, err = transport.ReadResponse(conn, req)
	if err == nil {
		transport.PutConnection(conn)
	}

	fmt.Printf("\n\n RESPONSE %s\n\n", flow.Response)
	return err
}

func BuildErrorResponse(outreq *http.Request, err error) *http.Response {
	// create an HTTP response with appropriate
	// status code
	resp := &http.Response{
		Request:       outreq,
		Proto:         outreq.Proto,
		ProtoMajor:    outreq.ProtoMajor,
		ProtoMinor:    outreq.ProtoMinor,
		Header:        make(http.Header, 0),
		Body:          http.NoBody,
		ContentLength: int64(0),
	}
	switch err {
	case ErrHttpUnauthorized:
		resp.StatusCode = http.StatusUnauthorized
	case ErrHttpBadRequest:
		resp.StatusCode = http.StatusBadRequest
	case ErrHttpForbiddenRequest:
		resp.StatusCode = http.StatusForbidden
	default:
		// default to bad gateway for S3 server conn. errors
		resp.StatusCode = http.StatusBadGateway
	}
	resp.Status = strconv.Itoa(resp.StatusCode) + " " + err.Error()
	return resp
}

func (p *HttpMitmProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay
	if req.ContentLength == 0 {
		outreq.Body = nil
	}

	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	copiedHeaders := false
	if c := outreq.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					copyHeader(outreq.Header, req.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(f)
			}
		}
	}
	// Remove hop-by-hop headers to the backend.  Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.  This
	// is modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	// create the flow object
	flow := &HttpFlow{
		Id:       Uuid(),
		Request:  outreq,
		Response: nil,
	}

	// check if this request should be streamed
	if p.streamRequestData(flow) {
		flow.RequestStreaming = true
	}

	//send this request on its way out
	err := p.processRequest(flow)
	if err != nil {
		resp := BuildErrorResponse(outreq, err)
		flow.Response = resp
	}
	if flow.Request.Body != nil {
		flow.Request.Body.Close()
	}
	defer flow.Response.Body.Close()

	for _, h := range hopHeaders {
		flow.Response.Header.Del(h)
	}
	_, err = p.processResponse(rw, flow)
	if err != nil {
		p.app.FailureHandler(flow)
	}
}

func (p *HttpMitmProxy) processResponse(dst http.ResponseWriter, flow *HttpFlow) (written int64, err error) {

	resp := flow.Response
	if p.streamResponseData(flow) {
		flow.ResponseStreaming = true
	}

	p.app.ResponseHandler(flow)
	if flow.ResponseStreaming == true {
		origContentLength := resp.ContentLength
		copyHeader(dst.Header(), flow.Response.Header)
		dst.WriteHeader(flow.Response.StatusCode)

		src := resp.Body
		respBytesSeen := int64(0)
		for {
			buf := p.BufferPool.Get()
			nr, err := io.ReadFull(src, buf)
			if nr > 0 {
				respBytesSeen += int64(nr)
				// invoke the application callback, if registered
				// app may modify the request and return a different
				// buffer. Also buffer here needs to be larger than
				// the data being read, so that app handler can
				// modify contents and return update buffer.
				last_chunk := (respBytesSeen == origContentLength)
				data, _ := p.app.StreamedResponseDataHandler(flow, buf[0:nr], last_chunk)
				nr = len(data)
				nw, ew := dst.Write(data)
				if nw > 0 {
					written += int64(nw)
				}
				if ew != nil {
					err = ew
					p.BufferPool.Put(buf)
					break
				}
				if nr != nw {
					err = ErrResponseShortWrite
					p.BufferPool.Put(buf)
					break
				}
				if last_chunk {
					p.BufferPool.Put(buf)
					break
				}
			}
			if err == io.EOF {
				p.BufferPool.Put(buf)
				break
			}
			p.BufferPool.Put(buf)
		}
	} else {
		if flow.Request.Method != "HEAD" && resp.ContentLength > 0 {
			src := resp.Body
			buf := p.BufferPool.Get()
			nr, err := io.ReadFull(src, buf)
			if err == io.EOF {
				p.BufferPool.Put(buf)
				return written, err
			}
			if nr > 0 {
				data, err := p.app.ResponseDataHandler(flow, buf[0:nr])
				if err != nil {
					flow.Response = BuildErrorResponse(flow.Request, err)
					copyHeader(dst.Header(), flow.Response.Header)
					dst.WriteHeader(flow.Response.StatusCode)
					return 0, nil
				}
				nr = len(data)

				//write the updated headers first
				copyHeader(dst.Header(), flow.Response.Header)
				dst.WriteHeader(flow.Response.StatusCode)

				//next write the body
				nw, ew := dst.Write(data)
				if nw > 0 {
					written += int64(nw)
				}
				p.BufferPool.Put(buf)
				if ew != nil {
					return written, ew
				}
				if nr != nw {
					err = ErrResponseShortWrite
					return written, ew
				}
			}
		} else if chunked(resp.TransferEncoding) && resp.Body != http.NoBody {
			// aws uses TransferEncoding = chunked for metadata requests only
			//
			buf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return 0, err
			}
			data, _ := p.app.ResponseDataHandler(flow, buf)
			nr := len(data)

			//write the updated headers first
			copyHeader(dst.Header(), flow.Response.Header)
			dst.WriteHeader(flow.Response.StatusCode)

			//next write the body
			nw, ew := dst.Write(data)
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				err = ErrResponseShortWrite
				return written, ew
			}
		} else {
			//response with no body
			p.app.ResponseDataHandler(flow, nil)
			copyHeader(dst.Header(), flow.Response.Header)
			dst.WriteHeader(flow.Response.StatusCode)
			return 0, nil
		}
	}
	return written, err
}
