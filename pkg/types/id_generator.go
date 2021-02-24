package types

import (
	"errors"
	"sync"
)

// IDGenerator is used to allocate RAN UE NGAP ID or TEID
type IDGenerator struct {
	sync.Mutex
	IDGeneratorBasic
}

// IDGeneratorBasic is used to allocate RAN UE NGAP ID or TEID
type IDGeneratorBasic struct {
	Standard  int64
	Offset    uint64
	Threshold uint64
}

// NewIDGenerator sets the IDGenerator to the database for a RANUENGAPID IDGenerator or TEID IDGenerator
func NewIDGenerator(minValue int64, maxValue int64) *IDGenerator {
	idGenerator := &IDGenerator{}
	idGenerator.Standard = minValue
	idGenerator.Offset = 0
	idGenerator.Threshold = uint64(maxValue) - uint64(minValue) + 1

	return idGenerator
}

// Allocate is used to allocate a RAN UE NGAP ID or TEID
func (idGenerator *IDGenerator) Allocate() (id int64, err error) {
	idGenerator.Mutex.Lock()
	defer idGenerator.Mutex.Unlock()

	if idGenerator.Offset == idGenerator.Threshold {
		err = errors.New("No value range available to allocate a RANUENGAPID or TEID")
	}

	id = idGenerator.Standard + int64(idGenerator.Offset)
	idGenerator.Offset++
	return
}
