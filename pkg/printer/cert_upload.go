package printer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const urlCertImport = "/net/security/certificate/import.html"
const urlCertImportWait = "/net/security/certificate/certificate_wait.html"
const certImportPassword = "brother"

// UploadNewCert converts the specified pem files into p12 format and installs them
// on the printer. It returns the id value of the newly installed cert.
func (p *printer) UploadNewCert(keyPem, certPem []byte) (string, error) {
	// make p12 from key and cert pem
	p12, err := makeModernPfx(keyPem, certPem, certImportPassword)
	if err != nil {
		return "", fmt.Errorf("printer: failed to make p12 file (%w)", err)
	}
	var bodyBytes []byte

	// GET current cert IDs
	origCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}
	origSerials := map[string]string{}
	for _, id := range origCertIDs {
		if s, err := p.getCertIDSerial(id); err == nil {
			origSerials[id] = hex.EncodeToString(s)
		}
	}

	// GET import page to obtain CSRFToken
	// get url & set path
	u, err := url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: get of certificate import page failed (status code %d)", resp.StatusCode)
	}

	// find CSRFToken
	csrfToken, err := parseBodyForCSRFToken(bodyBytes)
	if err != nil {
		return "", err
	}

	// make writer for multipart/form-data submission
	var formDataBuffer bytes.Buffer
	formWriter := multipart.NewWriter(&formDataBuffer)

	// make form fields
	err = formWriter.WriteField("pageid", "388")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("CSRFToken", csrfToken)
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// fields observed on this model's import form
	err = formWriter.WriteField("B12b2", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.WriteField("B12c0", "")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// control 1 for upload, 2 for finalize (matches observed browser sequence)
	err = formWriter.WriteField("hidden_certificate_process_control", "1")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// file field is B11b0 on this model
	p12W, err := formWriter.CreateFormFile("B11b0", "certkey.p12")
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	_, err = io.Copy(p12W, bytes.NewReader(p12))
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// password field on page
	err = formWriter.WriteField("B11b1", certImportPassword)
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	// hidden password (present on page, empty by default)
	err = formWriter.WriteField("hidden_cert_import_password", certImportPassword)
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to write form (%w)", err)
	}

	err = formWriter.Close()
	if err != nil {
		return "", fmt.Errorf("printer: upload: failed to close form (%w)", err)
	}

	// get url & set path
	u, err = url.ParseRequestURI(p.baseUrl)
	if err != nil {
		return "", err
	}
	u.Path = urlCertImport

	// make and do request
	req, err = http.NewRequest(http.MethodPost, u.String(), &formDataBuffer)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())

	resp, err = p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// read body of response
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// OK status?
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("printer: post of new certificate failed (status code %d)", resp.StatusCode)
	}

	// try to get fresh CSRF token returned after upload; fall back to original
	nextCsrf := csrfToken
	if t, err := parseBodyForCSRFToken(bodyBytes); err == nil && t != "" {
		nextCsrf = t
	}

	// finalize import with second form (mirrors browser flow on this model)
	finalizeData := url.Values{}
	finalizeData.Set("pageid", "388")
	finalizeData.Set("CSRFToken", nextCsrf)
	finalizeData.Set("B12b2", "")
	finalizeData.Set("B12b3", "")
	finalizeData.Set("hidden_certificate_process_control", "2")
	finalizeData.Set("hidden_cert_import_password", certImportPassword)

	// try finalize to wait page first, then fallback to import.html if 404
	finalizePaths := []string{urlCertImportWait, urlCertImport}
	for _, path := range finalizePaths {
		u.Path = path

		req, err = http.NewRequest(http.MethodPost, u.String(), strings.NewReader(finalizeData.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = p.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		// read body of response
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		if resp.StatusCode == http.StatusOK {
			break
		}
	}

	// normally the webUI would show a waiting screen for ~7 seconds. insert
	// a delay here to account for any processing the device might do
	// before next steps
	time.Sleep(10 * time.Second)

	// get new cert ID list
	newCertIDs, err := p.getCertIDs()
	if err != nil {
		return "", err
	}
	newSerials := map[string]string{}
	for _, id := range newCertIDs {
		if s, err := p.getCertIDSerial(id); err == nil {
			newSerials[id] = hex.EncodeToString(s)
		}
	}

	// find ID that is in new list but not in old (this is the new one)
	newId := ""
	countNew := 0
	for i := range newCertIDs {
		found := false

		// check if existed originally
		for j := range origCertIDs {
			if newCertIDs[i] == origCertIDs[j] {
				found = true
				break
			}
		}

		if !found {
			newId = newCertIDs[i]
			countNew++
		}
	}

	// if no new id was added, check for serial change on existing IDs (replacement-in-place)
	if newId == "" {
		for id, serial := range newSerials {
			if oldSerial, ok := origSerials[id]; ok && oldSerial != serial {
				newId = id
				countNew = 1
				break
			}
		}
	}

	// if more than one new, can't determine which was uploaded by this app
	if countNew > 1 {
		return "", errors.New("printer: upload: failed to deduce new cert's id")
	}

	if newId == "" {
		return "", errors.New("printer: upload: did not detect new cert id (upload may have failed)")
	}

	return newId, nil
}
