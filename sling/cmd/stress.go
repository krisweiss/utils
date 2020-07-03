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

package cmd

import (
	"context"
	"os"
	"os/signal"
	"sling/internal"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// stress command base variables
var (
	duration int
	requests int
	workers  int
)

// monitor variables
var (
	monitor  bool
	port     string
	user     string
	password string
)

// stressCmd represents the stress command
var stressCmd = &cobra.Command{
	Use:   "stress",
	Short: "Stress tests target with a constant load",
	Long: `Sends a constant stream of requests for a set duration.
The monitor option streams the top output over ssh.
	
Example:
  sling stress -U http://www.example.com/ --monitor -u root -p supersecretpassword`,

	Run: func(cmd *cobra.Command, args []string) {
		t := internal.Target{
			Address: url,
			Method:  method,
			Headers: headers,
			Body:    body,
			Timeout: time.Millisecond * time.Duration(timeout),
			Cert:    cert,
			Key:     key,
			CA:      ca,
		}
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt)
		stopMonitor := make(chan struct{}, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			signal.Stop(signalChan)
			close(signalChan)
			close(stopMonitor)
		}()
		go func() {
			select {
			case <-signalChan:
				cancel()
			}
		}()
		var wg sync.WaitGroup
		if monitor && user != "" && password != "" {
			m := internal.Monitor{
				Host:     url,
				Port:     port,
				User:     user,
				Password: password,
			}
			go func() {
				wg.Add(1)
				m.Observe(ctx, &wg)
			}()
		}

		t.Stress(ctx, duration, workers, requests)
		if monitor {
			cancel()
		}

		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(stressCmd)

	stressCmd.Flags().StringVarP(&url, "url", "U", "", "Target URL")
	stressCmd.Flags().StringVarP(&method, "method", "m", "GET", "Request method")
	stressCmd.Flags().StringVarP(&headers, "headers", "H", "", "Example: -H \"header: value, header: value,...\"")
	stressCmd.Flags().StringVarP(&body, "body", "b", "", "Request body")
	stressCmd.Flags().IntVarP(&timeout, "timeout", "t", 1000, "Request timeout in milliseconds")
	stressCmd.Flags().StringVarP(&cert, "cert", "", "", "PEM encoded certificate")
	stressCmd.Flags().StringVarP(&key, "key", "", "", "PEM encoded private key")
	stressCmd.Flags().StringVarP(&ca, "ca", "", "", "PEM encoded CA's certificate")
	// stress-only flags
	stressCmd.Flags().IntVarP(&duration, "duration", "d", 5, "Duration of test")
	stressCmd.Flags().IntVarP(&workers, "workers", "w", 100, "Number of workers")
	stressCmd.Flags().IntVarP(&requests, "requests", "r", 200, "Requests per second")
	// monitor flags
	stressCmd.Flags().BoolVarP(&monitor, "monitor", "", false, "Toggle monitoring over ssh")
	stressCmd.Flags().StringVarP(&port, "port", "", "22", "SSH port")
	stressCmd.Flags().StringVarP(&user, "user", "u", "", "SSH username")
	stressCmd.Flags().StringVarP(&password, "password", "p", "", "SSH password")

	stressCmd.MarkFlagRequired("url")
}
