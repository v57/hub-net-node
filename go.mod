module github.com/v57/hub-net-node

go 1.25.0

require (
	github.com/v57/hub-service-go v0.1.0
	golang.org/x/net v0.38.0
)

require golang.org/x/sys v0.31.0 // indirect

replace github.com/v57/hub-service-go => ../hub-service-go
