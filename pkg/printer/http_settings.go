package printer

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const urlHttpCertServerSettings = "net/net/certificate/http.html"

var (
	errCurrentCertIdNotFound = errors.New("printer: get: failed to find current cert id")
)

// getHttpSettings fetches the HTTP Server Settings page
func (p *printer) getHttpSettings() ([]byte, error) {
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return nil, err
	}
	u.Path = urlHttpCertServerSettings

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// handle single redirect manually (client is set to not follow)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			redirectURL, err := url.Parse(loc)
			if err == nil {
				if !redirectURL.IsAbs() {
					redirectURL = req.URL.ResolveReference(redirectURL)
				}
				resp.Body.Close()
				req2, err := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
				if err != nil {
					return nil, err
				}
				resp, err = p.httpClient.Do(req2)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
			}
		}
	}

	// read body of response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("printer: get of http settings page failed (status code %d)", resp.StatusCode)
	}

	return bodyBytes, nil
}

// SetActiveCert sets the printers active certificate the specified ID and
// then restarts the printer (to make the new cert active)
// Note: This function even works of the `id` is not in the dropdown box of the printer's
// cert picker (which happens when the cert does not have a Common Name)
func (p *printer) SetActiveCert(id string) error {
	parseFormForID := func(body []byte, target string, defaultPath string) (actionPath string, fields map[string]string) {
		actionPath = defaultPath
		fields = map[string]string{}

		formRe := regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']+)["'][^>]*>(.*?)</form>`)
		selectRe := regexp.MustCompile(`(?is)<select[^>]*name=["']([^"']+)["'][^>]*>(.*?)</select>`)
		optionRe := regexp.MustCompile(`(?i)<option[^>]*value=["']([^"']+)["']`)
		inputRe := regexp.MustCompile(`(?i)<input[^>]*>`)
		typeRe := regexp.MustCompile(`(?i)type=["']([^"']+)["']`)
		nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
		valRe := regexp.MustCompile(`(?i)value=["']([^"']*)["']`)
		checkedRe := regexp.MustCompile(`(?i)checked`)

		for _, fm := range formRe.FindAllSubmatch(body, -1) {
			rawAction := string(fm[1])
			inner := fm[2]

			// find select with the target id
			hasTarget := false
			for _, sm := range selectRe.FindAllSubmatch(inner, -1) {
				selName := string(sm[1])
				options := sm[2]
				for _, om := range optionRe.FindAllSubmatch(options, -1) {
					if string(om[1]) == target {
						// set select to target
						fields[selName] = target
						hasTarget = true
						break
					}
				}
				if hasTarget {
					break
				}
			}
			if !hasTarget {
				continue
			}

			// resolve action path
			if u, err := url.Parse(rawAction); err == nil {
				if u.Path != "" {
					if strings.HasPrefix(u.Path, "/") {
						actionPath = u.Path
					} else {
						actionPath = path.Join(path.Dir("/"+defaultPath), u.Path)
					}
				}
			} else {
				if strings.HasPrefix(rawAction, "/") {
					actionPath = rawAction
				} else {
					actionPath = path.Join(path.Dir("/"+defaultPath), rawAction)
				}
			}

			// parse inputs in this form
			for _, inp := range inputRe.FindAll(inner, -1) {
				typ := ""
				if m := typeRe.FindSubmatch(inp); len(m) == 2 {
					typ = strings.ToLower(string(m[1]))
				}
				name := ""
				if m := nameRe.FindSubmatch(inp); len(m) == 2 {
					name = string(m[1])
				}
				if name == "" {
					continue
				}
				val := ""
				if m := valRe.FindSubmatch(inp); len(m) == 2 {
					val = string(m[1])
				}
				switch typ {
				case "hidden", "password", "text":
					fields[name] = val
				case "checkbox", "radio":
					if checkedRe.Match(inp) {
						if val == "" {
							val = "1"
						}
						fields[name] = val
					}
				default:
					// ignore
				}
			}

			break
		}

		return actionPath, fields
	}

	// GET http settings
	bodyBytes, err := p.getHttpSettings()
	if err != nil {
		return err
	}
	_ = os.WriteFile("/tmp/http_settings_get.html", bodyBytes, 0o600)
	log.Printf("http settings GET status=200 body_len=%d saved=/tmp/http_settings_get.html", len(bodyBytes))

	actionPath, hidden := parseFormForID(bodyBytes, id, urlHttpCertServerSettings)
	csrfToken, _ := hidden["CSRFToken"]
	if csrfToken == "" {
		if t, err := parseBodyForCSRFToken(bodyBytes); err == nil {
			csrfToken = t
		}
	}

	// submit initial form to change the cert
	data := url.Values{}
	for k, v := range hidden {
		data.Set(k, v)
	}
	if !data.Has("pageid") {
		data.Set("pageid", "326")
	}
	data.Set("CSRFToken", csrfToken)
	// ensure cert selection present
	if !data.Has("B903") {
		data.Set("B903", id)
	}
	// ensure HTTPS toggles enabled if present and empty
	if data.Get("B86c") == "" {
		data.Set("B86c", "1")
	}
	if data.Get("B87e") == "" {
		data.Set("B87e", "1")
	}
	// if https toggles exist, preserve as-is; otherwise leave defaults

	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return err
	}
	u.Path = actionPath

	// make and do request
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", u.String())

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = os.WriteFile("/tmp/http_settings_post1.html", bodyBytes, 0o600)
	log.Printf("http settings POST1 status=%d body_len=%d saved=/tmp/http_settings_post1.html", resp.StatusCode, len(bodyBytes))
	if loc := resp.Header.Get("Location"); loc != "" {
		log.Printf("http settings POST1 location=%s", loc)
	}

	// OK status?
	if resp.StatusCode >= 400 {
		return errors.New("printer: failed to post set active cert form")
	}

	// Refresh page after first post to get latest CSRF/hidden/action
	bodyBytes, err = p.getHttpSettings()
	if err != nil {
		return err
	}
	_ = os.WriteFile("/tmp/http_settings_post1_refresh.html", bodyBytes, 0o600)
	log.Printf("http settings GET after POST1 body_len=%d saved=/tmp/http_settings_post1_refresh.html", len(bodyBytes))

	actionPath, hidden = parseFormForID(bodyBytes, id, urlHttpCertServerSettings)
	csrfToken, _ = hidden["CSRFToken"]
	if csrfToken == "" {
		if t, err := parseBodyForCSRFToken(bodyBytes); err == nil {
			csrfToken = t
		}
	}

	// submit confirmation (& reboot now)
	data = url.Values{}
	for k, v := range hidden {
		data.Set(k, v)
	}
	if !data.Has("pageid") {
		data.Set("pageid", "326")
	}
	data.Set("CSRFToken", csrfToken)
	// force immediate reboot/activate other secure protocols
	data.Set("http_page_mode", "5")
	if data.Get("active_other_protocol") == "" {
		data.Set("active_other_protocol", "1")
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

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, _ = io.ReadAll(resp.Body)
	_ = os.WriteFile("/tmp/http_settings_post2.html", bodyBytes, 0o600)
	log.Printf("http settings POST2 status=%d body_len=%d saved=/tmp/http_settings_post2.html", resp.StatusCode, len(bodyBytes))

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return errors.New("printer: failed to post set active cert form")
	}

	// give the printer a moment to process/reboot
	time.Sleep(5 * time.Second)

	return nil
}
