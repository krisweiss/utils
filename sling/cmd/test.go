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
	"time"

	"github.com/spf13/cobra"
)

var (
	url     string
	method  string
	headers string
	body    string
	timeout int
	cert    string
	key     string
	ca      string
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Load tests target to establish a baseline",
	Long: `Run a series of tests to establish the maximum requests per second
without any errors in the response.

Example: 
  sling test -U https://www.example.com/`,

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

		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			signal.Stop(signalChan)
			cancel()
			close(signalChan)
		}()
		go func() {
			select {
			case <-signalChan:
				cancel()
			}
		}()
		t.Test(ctx)
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().StringVarP(&url, "url", "U", "", "Target URL")
	testCmd.Flags().StringVarP(&method, "method", "m", "GET", "Request method")
	testCmd.Flags().StringVarP(&headers, "headers", "H", "", "Example: -H \"header: value, header: value,...\"")
	testCmd.Flags().StringVarP(&body, "body", "b", "", "Request body")
	testCmd.Flags().IntVarP(&timeout, "timeout", "t", 1000, "Request timeout in milliseconds")
	testCmd.Flags().StringVarP(&cert, "cert", "", "", "PEM encoded certificate")
	testCmd.Flags().StringVarP(&key, "key", "", "", "PEM encoded private key")
	testCmd.Flags().StringVarP(&ca, "ca", "", "", "PEM encoded CA's certificate")

	testCmd.MarkFlagRequired("url")
}
