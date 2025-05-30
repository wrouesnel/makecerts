package util

func AppendIfNotBlank(arr []string, s string) []string {
	if s != "" {
		return append(arr, s)
	}
	return arr
}
