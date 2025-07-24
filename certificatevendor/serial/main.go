package serial

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

type Serial struct {
	serial  *atomic.Uint64
	writeMu sync.Mutex
}

func New() (*Serial, error) {
	serial := &atomic.Uint64{}
	storedSerial, err := loadSerial()
	if err != nil {
		return nil, err
	}
	serial.Store(storedSerial)
	return &Serial{
		serial: serial,
	}, nil
}

// loadSerial reads in a stored serial number.
// Returns 0 if the serial number doesn't exist.
// Returns an error if there’s a problem reading or decoding the file.
func loadSerial() (uint64, error) {
	// Check if the file exists
	path := "serial_number"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("stat %q: %w", path, err)
	}

	// Open the file for reading
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	// Read 8 bytes into a uint64
	var v uint64
	if err := binary.Read(f, binary.BigEndian, &v); err != nil {
		return 0, fmt.Errorf("decode %q: %w", path, err)
	}

	return v, nil
}

func (s *Serial) GetSerial() uint64 {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	serial := s.serial.Add(1)
	saveSerial(serial)
	return serial
}

func saveSerial(serial uint64) error {
	path := "serial_number"
	tmp := path + ".tmp"

	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, serial); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
