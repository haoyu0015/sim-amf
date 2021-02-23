module sim-amf

replace free5gc => ./free5gc

go 1.15

require (
	free5gc v0.0.0-00010101000000-000000000000
	github.com/davecgh/go-spew v1.1.1
	github.com/spf13/cobra v0.0.5
	gitlab.casa-systems.com/mobility/agf/schema v0.0.7
	gitlab.casa-systems.com/opensource/sctp v0.0.0-20200717184436-d2a6e2ad767c
	gitlab.casa-systems.com/platform/go/axyom v0.2.0
	google.golang.org/grpc v1.27.1
)
