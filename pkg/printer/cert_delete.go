package printer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

const urlCertDelete = "/net/security/certificate/delete.html"

var errCertDeleteInvalidID = errors.New("printer: cant delete cert (invalid id)")

// DeleteCert deletes the certificate with the specified ID from the
// printer
func (p *printer) DeleteCert(id string) error {
	parseDeleteForm := func(body []byte, defaultPath string) (action string, fields map[string]string) {
		action = defaultPath
		fields = map[string]string{}

		formRe := regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']+)["'][^>]*>(.*?)</form>`)
		inputRe := regexp.MustCompile(`(?i)<input[^>]*type=["']hidden["'][^>]*>`)
		nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
		valRe := regexp.MustCompile(`(?i)value=["']([^"']*)["']`)

		for _, fm := range formRe.FindAllSubmatch(body, -1) {
			rawAction := string(fm[1])
			inner := fm[2]

			// prefer forms that look like delete (action contains delete or has hidden_certificate_idx)
			if !strings.Contains(strings.ToLower(rawAction), "delete") && !bytes.Contains(inner, []byte("hidden_certificate_idx")) {
				continue
			}

			if u, err := url.Parse(rawAction); err == nil {
				if u.Path != "" {
					if strings.HasPrefix(u.Path, "/") {
						action = u.Path
					} else {
						action = path.Join(path.Dir("/"+defaultPath), u.Path)
					}
				}
			} else {
				if strings.HasPrefix(rawAction, "/") {
					action = rawAction
				} else {
					action = path.Join(path.Dir("/"+defaultPath), rawAction)
				}
			}

			for _, tag := range inputRe.FindAll(inner, -1) {
				name := ""
				if m := nameRe.FindSubmatch(tag); len(m) == 2 {
					name = string(m[1])
				}
				if name == "" {
					continue
				}
				val := ""
				if m := valRe.FindSubmatch(tag); len(m) == 2 {
					val = string(m[1])
				}
				fields[name] = val
			}

			break
		}

		if len(fields) == 0 {
			// fallback: parse all hidden inputs
			inputs := parseHidden(body)
			for k, v := range inputs {
				fields[k] = v
			}
		}

		return action, fields
	}

	// verify ID actually exists and isn't 0 ('Preset') which isn't valid
	if len(id) <= 0 || id == "0" {
		return errCertDeleteInvalidID
	}

	existingIDs, err := p.getCertIDs()
	if err != nil {
		return err
	}

	validID := false
	for _, existingID := range existingIDs {
		if existingID == id {
			validID = true
			break
		}
	}
	if !validID {
		return errCertDeleteInvalidID
	}

	// first get the delete page to get CSRFToken
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	actionPath := urlCertDelete
	u.Path = actionPath
	referer := u.String()

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	// req query
	query := req.URL.Query()
	query.Set("idx", id)
	req.URL.RawQuery = query.Encode()

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// OK status?
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("printer: get of delete page failed (status code %d)", resp.StatusCode)
	}

	actionPath, hidden := parseDeleteForm(bodyBytes, urlCertDelete)
	hidden["idx"] = id
	if _, ok := hidden["hidden_certificate_idx"]; ok {
		hidden["hidden_certificate_idx"] = id
	}

	// first delete form
	data := url.Values{}
	for k, v := range hidden {
		data.Set(k, v)
	}
	// if process control present, set to 1 on first post
	if data.Has("hidden_certificate_process_control") {
		data.Set("hidden_certificate_process_control", "1")
	}
	// ensure pageid present
	if !data.Has("pageid") {
		data.Set("pageid", "383")
	}
	// ensure CSRF present
	if !data.Has("CSRFToken") {
		if csrfToken, err := parseBodyForCSRFToken(bodyBytes); err == nil {
			data.Set("CSRFToken", csrfToken)
		}
	}

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = actionPath

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Set("idx", id)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// OK status?
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("printer: get failed (status code %d)", resp.StatusCode)
	}

	actionPath, hidden = parseDeleteForm(bodyBytes, urlCertDelete)
	hidden["idx"] = id
	if _, ok := hidden["hidden_certificate_idx"]; ok {
		hidden["hidden_certificate_idx"] = id
	}

	// second delete (confirmation) form
	// form values
	data = url.Values{}
	for k, v := range hidden {
		data.Set(k, v)
	}
	// second post: set process control to 2 if present
	if data.Has("hidden_certificate_process_control") {
		data.Set("hidden_certificate_process_control", "2")
	}
	if !data.Has("pageid") {
		data.Set("pageid", "383")
	}
	if !data.Has("CSRFToken") {
		if csrfToken, err := parseBodyForCSRFToken(bodyBytes); err == nil {
			data.Set("CSRFToken", csrfToken)
		}
	}

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = actionPath

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	q = req.URL.Query()
	q.Set("idx", id)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read and discard entire body
	bodyBytes, _ = io.ReadAll(resp.Body)

	// normally the webUI would show a waiting screen for ~7 seconds. insert
	// a delay here to account for any processing the device might do
	// before next steps
	time.Sleep(5 * time.Second)

	// poll for deletion, allowing extra time for slower devices
	const (
		maxAttempts = 6
		delay       = 5 * time.Second
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		existingIDs, err := p.getCertIDs()
		if err != nil {
			// try again unless last attempt
			if attempt == maxAttempts {
				return err
			}
			time.Sleep(delay)
			continue
		}

		idFound := false
		for _, existingID := range existingIDs {
			if existingID == id {
				idFound = true
				break
			}
		}
		if !idFound {
			return nil
		}

		// still present, wait and retry
		time.Sleep(delay)
	}

	return errors.New("printer: failed to delete cert (still exists)")
}
