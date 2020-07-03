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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
)

// Result holds the response data from the request
type Result struct {
	Time   time.Duration
	Status string
	Err    string
}

// SyncResultSlice provedes a safe wrapper for the Results slice
type SyncResultSlice struct {
	results []Result
	mutex   sync.Mutex
}

// Target defines the server and the request parameters we want to test
type Target struct {
	Address   string
	Method    string
	Headers   string
	Body      string
	Timeout   time.Duration
	Cert      string
	Key       string
	CA        string
	TLSconfig *tls.Config
}

// Tickle tests the target for availability
func (t *Target) Tickle() error {
	fmt.Println(time.Now().Local().Format(time.UnixDate), "\tAcquiring target")
	client := t.client()
	request := t.request()
	response, err := client.Do(request)
	if err != nil {
		slice := strings.Split(fmt.Sprint(err), ":")
		return errors.New(strings.TrimSpace(slice[len(slice)-1]))
	}
	if response.StatusCode < 200 && response.StatusCode > 299 {
		return errors.New(response.Status)
	}
	fmt.Println(time.Now().Local().Format(time.UnixDate), "\tServer identified as:", response.Header.Get("Server"))
	return nil
}

// Test runs multiple load tests on target to establish a basline
func (t *Target) Test(ctx context.Context) {
	if err := t.Tickle(); err != nil {
		fmt.Println(time.Now().Local().Format(time.UnixDate), "\tFailed:", err)
		os.Exit(1)
	}
	results := [][]Result{}

	minError := math.MaxInt64
	maxSuccess := 0
	nRequests := 50
	hasErrors := false
	fmt.Println(time.Now().Local().Format(time.UnixDate), "\tStarting test")
	for (minError - maxSuccess) > 10 {
		if hasErrors {
			nRequests = minError - ((minError - maxSuccess) / 2)
			hasErrors = false
		} else if minError < nRequests*2 || nRequests*2 < maxSuccess {
			nRequests = maxSuccess + ((minError - maxSuccess) / 2)
		} else {
			nRequests *= 2
		}
		result, err, stop := t.loadTest(ctx, nRequests, nRequests, time.Second*time.Duration(5), true)
		results = append(results, result)
		if err {
			minError = nRequests
			hasErrors = err
		} else {
			maxSuccess = nRequests
		}
		errorCount := 0
		var responseTime time.Duration
		for _, r := range result {
			if r.Err != "" {
				errorCount++
			}
			responseTime += r.Time
		}

		avgResTime := float64(responseTime.Microseconds()) / float64(len(result)) / 1000

		errorRate := errPercent(errorCount, len(result))
		fmt.Printf("%v   Requests per second: %v, error rate: %0.2f%%, average response time: %0.2f ms\n", time.Now().Local().Format(time.UnixDate), nRequests, errorRate, avgResTime)
		if stop {
			break
		}
	}
	fmt.Printf("%v\tMost requests per second reached: %v\n", time.Now().Local().Format(time.UnixDate), maxSuccess)

}

// Stress runs a prolonged load test as a stress test
func (t *Target) Stress(ctx context.Context, duration, workers, requests int) {

	if err := t.Tickle(); err != nil {
		fmt.Println(time.Now().Local().Format(time.UnixDate), "\tFailed:", err)
		os.Exit(1)
	}
	fmt.Println(time.Now().Local().Format(time.UnixDate), "\tStarting test")
	start := time.Now()
	result, _, _ := t.loadTest(ctx, workers, requests, time.Second*time.Duration(duration), false)
	errorCount := 0
	var responseTime time.Duration
	for _, r := range result {
		if r.Err != "" {
			errorCount++
		}
		responseTime += r.Time
	}

	avgResTime := float64(responseTime.Microseconds()) / float64(len(result)) / 1000
	errorRate := errPercent(errorCount, len(result))
	fmt.Printf("\n%v\tFinished\nRequests per second: \t\t%v\nWorkers used: \t\t\t%v\nTime elapsed: \t\t\t%0.2f s\nRequests sent: \t\t\t%v\nAverage response time: \t\t%0.2f ms\nError rate: \t\t\t%0.2f%%\n", time.Now().Local().Format(time.UnixDate), requests, workers, float64(time.Since(start).Milliseconds())/1000, len(result), avgResTime, errorRate)
}

// Run load tests the target
func (t *Target) loadTest(ctx context.Context, nWorkers int, nRequests int, duration time.Duration, showSpinner bool) ([]Result, bool, bool) {
	var wg sync.WaitGroup
	client := t.client()
	request := t.request()
	tickChan := make(chan struct{})
	resultChan := make(chan Result)
	results := SyncResultSlice{}

	spinner := spinner.New(spinner.CharSets[9], 100*time.Millisecond)

	for i := 0; i < nWorkers; i++ {
		go worker(client, request, tickChan, resultChan, &wg)
	}
	hasErrors := false

	go func() {
		for result := range resultChan {
			if result.Err != "" && hasErrors == false {
				hasErrors = true
			}
			results.mutex.Lock()
			results.results = append(results.results, result)
			results.mutex.Unlock()
		}
	}()
	if showSpinner {
		spinner.Start()
	}

	rate, err := getRate(nRequests)
	if err != nil {
		log.Fatalln(err)
	}

	stop := false
	start := time.Now()
Loop:
	for {
		if time.Since(start) >= duration {
			break Loop
		}
		begin := time.Now()
		pause, wait := throttle(begin, rate)
		if wait {
			time.Sleep(pause)
		}

		select {
		case <-ctx.Done():
			spinner.Stop()
			fmt.Printf("\n%v\tForcefully stopping\n", time.Now().Local().Format(time.UnixDate))
			stop = true
			break Loop
		default:
			wg.Add(1)
			tickChan <- struct{}{}
		}
	}
	close(tickChan)

	wg.Wait()
	close(resultChan)

	spinner.Stop()
	results.mutex.Lock()
	defer results.mutex.Unlock()
	return results.results, hasErrors, stop
}

// Creates a new request based on the target parameters
func (t *Target) request() *http.Request {
	body := io.ReadCloser(nil)
	if t.Body != "" {
		body = ioutil.NopCloser(strings.NewReader(t.Body))
	}

	req, err := http.NewRequest(t.Method, t.Address, body)
	if err != nil {
		log.Fatalln(err)
	}

	if t.Headers != "" {
		headers := strings.Split(t.Headers, ",")
		for _, header := range headers {
			h := strings.Split(header, ":")
			req.Header.Set(strings.TrimSpace(h[0]), strings.TrimSpace(h[1]))
		}
	}

	return req
}

// Creates a client, checks and implements the TLS config and timeout
func (t *Target) client() *http.Client {
	t.TLSconfig = t.processTLS()
	transport := &http.Transport{}
	if t.TLSconfig.RootCAs != nil {
		t.TLSconfig.BuildNameToCertificate()
		transport = &http.Transport{TLSClientConfig: t.TLSconfig}
	}

	return &http.Client{Timeout: t.Timeout, Transport: transport}
}

// Processes the certificates to create the TLS configuration
func (t *Target) processTLS() *tls.Config {
	tlsConfig := tls.Config{}

	if t.Cert == "" || t.Key == "" {
		return &tlsConfig
	}

	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		log.Fatalln(err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	// If CA empty don't verify servers certificate chain and host name
	if t.CA == "" {
		tlsConfig.InsecureSkipVerify = true
	} else {
		ca, err := ioutil.ReadFile(t.CA)
		if err != nil {
			fmt.Println("ioutil error")
			log.Fatal(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	tlsConfig.BuildNameToCertificate()
	return &tlsConfig
}

// Worker waits for ticks to send request
func worker(client *http.Client, req *http.Request, tickChan chan struct{}, resultChan chan Result, wg *sync.WaitGroup) {
	for range tickChan {
		result := Result{}
		start := time.Now()
		res, err := client.Do(req)
		if err != nil {
			result.Err = fmt.Sprint(err)
			resultChan <- result
			wg.Done()
			continue
		}
		elapsed := time.Since(start)
		result.Time = elapsed
		result.Status = res.Status
		resultChan <- result
		wg.Done()
	}
}

// Returns time of pause to throttle the request rate
func throttle(begin time.Time, rate time.Duration) (time.Duration, bool) {
	if time.Since(begin) < rate {
		return (rate - time.Since(begin)), true
	}
	return rate, false
}

// Returns time of interval between requests
func getRate(nRequests int) (time.Duration, error) {
	rate := 1e9 / nRequests
	return time.ParseDuration(strconv.Itoa(rate) + "ns")
}

// Returns percentage of errors and avoids devide by zero error
func errPercent(errorCount, nRequests int) float64 {
	if nRequests < 100 {
		return 0.01
	}
	return float64(errorCount) / (float64(nRequests) / 100)
}
