package main

import (
	"flag"
	"github.com/golmaall/raksh"
	"net/url"
	"os"
)

type RakshProxy struct {
	description string
}

func (proxy *RakshProxy) RequestHandler(flow *reverseproxy.HttpFlow) error {

	req := flow.Request

	// Add a dummy header to the request
	return nil
}

func main() {
	var chunkSize = flag.Int64("chunk", 128*1024, "Chunk size to use for streaming")
	var (
		certFile string
		keyFile  string
	)
	flag.StringVar(&certFile, "cert-file", "", "SSL Certificate for backend to be proxied")
	flag.StringVar(&keyFile, "key-file", "", "SSL Certificate Key for backend to be proxied")
	flag.Parse()

	app := RakshProxy{description: "Sample MITM Proxy"}

	mitmProxy, _ := raksh.NewHttpMitmProxy(":8443", app, certFile, keyFile)

	httpRevProxy.Start()
}
