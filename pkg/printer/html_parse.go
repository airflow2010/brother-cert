package printer

import "regexp"

// parseHidden extracts all hidden input fields from a response body and returns
// them as a name/value map.
func parseHidden(body []byte) map[string]string {
	fields := map[string]string{}

	inputRe := regexp.MustCompile(`(?i)<input[^>]*type=["']hidden["'][^>]*>`)
	nameRe := regexp.MustCompile(`(?i)name=["']([^"']+)["']`)
	valRe := regexp.MustCompile(`(?i)value=["']([^"']*)["']`)

	for _, tag := range inputRe.FindAll(body, -1) {
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

	return fields
}
