/*
Copyright © 2020 Kristijan Weiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package internal

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
)

// Monitor holds the host credentials
type Monitor struct {
	Host     string
	Port     string
	User     string
	Password string
}

// Observe starts ssh session and streams top
func (m *Monitor) Observe(ctx context.Context, wg *sync.WaitGroup) {
	cmd := fmt.Sprintf("top -d 1")

	client := m.sshClient()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				fmt.Fprint(stdin, "q")
				if err := session.Wait(); err != nil {
					log.Fatal(err)
				}
				session.Close()
				client.Close()
				wg.Done()
				return
			}
		}
	}()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.ECHOCTL:       0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	height, width, err := terminal.GetSize(0)
	if err != nil {
		log.Fatal(err)
	}
	term := os.Getenv("TERM")
	err = session.RequestPty(term, width, height, modes)
	if err != nil {
		log.Fatal(err)
	}
	err = session.Start(cmd)
	if err != nil {
		log.Fatal(err)
	}
}

// Setup ssh client
func (m *Monitor) sshClient() *ssh.Client {
	hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal(err)
	}

	config := &ssh.ClientConfig{
		User: m.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(m.Password),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}

	address := strings.TrimRight(strings.TrimLeft(m.Host, "https://"), "/")

	client, err := ssh.Dial("tcp", address+":"+m.Port, config)
	if err != nil {
		log.Fatal(err)
	}
	return client
}
