// capture records raw ClientHellos to stdout, one hex line per connection.
// Used to regenerate testdata/clienthellos.txt when a client's TLS stack
// changes and the pinned fingerprints need refreshing.
//
//	go run ./cmd/capture > /tmp/hellos.txt
//	curl -sk https://127.0.0.1:8443/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Printf("capturing on %s, ctrl-c to stop", *listen)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))

			header := make([]byte, 5)
			if _, err := io.ReadFull(c, header); err != nil || header[0] != 0x16 {
				return
			}
			length := int(header[3])<<8 | int(header[4])
			if length > 1<<14 {
				return
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(c, body); err != nil {
				return
			}
			fmt.Println(hex.EncodeToString(append(header, body...)))
		}(c)
	}
}
