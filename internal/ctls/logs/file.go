package logs

import "os"

const (
	logPermissions = 0600
	logFlags       = os.O_APPEND | os.O_CREATE | os.O_WRONLY
)

type LogFile struct {
	file string
}

func (l LogFile) Write(p []byte) (int, error) {
	f, err := os.OpenFile(l.file, logFlags, logPermissions)
	if err != nil {
		return 0, err
	}

	defer func() { _ = f.Close() }()

	return f.Write(p)
}
