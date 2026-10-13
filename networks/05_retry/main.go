package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func newClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true, // новое соединение на каждую попытку
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 30x не обрабатываем, это итог
		},
	}
}

// код ответа, retry-after, ошибка
func doAttempt(client *http.Client, method, url, key string) (int, int, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, -1, err
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, -1, err
	}

	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // читаем тело, чтобы соединение закрыть
	
	retryAfter := -1
	if header := resp.Header.Get("Retry-After"); header != "" {
		if v, err := strconv.Atoi(header); err == nil && v >= 0 {
			retryAfter = v
		}
	}
	return resp.StatusCode, retryAfter, nil
}

func retryableStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

func canRetryMethod(method, key string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	case "POST":
		return key != ""
	}
	return false
}

func backoffMs(n int) int {
	ground := 200
	for i := 1; i < n; i++ {
		ground *= 2
		if ground > 2000 {
			ground = 2000
			break
		}
	}
	return rand.Intn(ground+1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: retry <url> [--method M] [--max-attempts N] [--idempotency-key K]")
		os.Exit(1)
	}
	url := os.Args[1]

	fs := flag.NewFlagSet("retry", flag.ExitOnError)
	methodFlag := fs.String("method", "GET", "HTTP method")
	maxAttempts := fs.Int("max-attempts", 5, "max attempts")
	key := fs.String("idempotency-key", "", "idempotency key")
	_ = fs.Parse(os.Args[2:]) // при ошибке сам завершит процесс
	
	method := strings.ToUpper(*methodFlag)
	client := newClient()
	methodRetryable := canRetryMethod(method, *key)
	attempts := 0
	success := false

	for n := 1; n <= *maxAttempts; n++ {
		attempts = n
		status, retryAfter, err := doAttempt(client, method, url, *key)

		shouldRetry := false
		if err != nil {
			fmt.Printf("attempt %d error %v\n", n, err)
			shouldRetry = true // нет ответа: это основание для повтора
		} else {
			fmt.Printf("attempt %d status %d\n", n, status)
			success = status >= 200 && status < 400
			shouldRetry = retryableStatus(status)
		}
		if !shouldRetry || !methodRetryable || n == *maxAttempts {
			break
		}
		sleep := backoffMs(n)
		if err == nil && retryAfter >= 0 {
			sleep = retryAfter * 1000
		}
		fmt.Printf("sleep_ms %d\n", sleep)
		time.Sleep(time.Duration(sleep) * time.Millisecond)
	}
	if success {
		fmt.Printf("result success attempts %d\n", attempts)
		os.Exit(0)
	}
	fmt.Printf("result failure attempts %d\n", attempts)
	os.Exit(1)
}
