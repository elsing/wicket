package admin

// firstChar returns the first character of a string, uppercased, for avatars.
func firstChar(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "?"
}

// itoa converts an int to its string representation without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if negative {
		result = "-" + result
	}
	return result
}

// eventClass returns a CSS class for an audit log event badge.
func eventClass(event string) string {
	if len(event) > 7 && event[:7] == "session" {
		return "event-session"
	}
	if len(event) > 6 && event[:6] == "device" {
		return "event-device"
	}
	if len(event) > 4 && event[:4] == "peer" {
		return "event-peer"
	}
	return "event-default"
}
