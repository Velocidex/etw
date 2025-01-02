module github.com/Velocidex/etw

go 1.13

require (
	github.com/Microsoft/go-winio v0.5.0
	github.com/Velocidex/ordereddict v0.0.0-20230909174157-2aa49cc5d11d
	github.com/Velocidex/ttlcache/v2 v2.9.1-0.20240517145123-a3f45e86e130
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.28.0
	www.velocidex.com/golang/binparsergen v0.1.1-0.20240404114946-8f66c7cf586e
	www.velocidex.com/golang/go-pe v0.1.1-0.20250101153735-7a925ba8334b
)

// replace www.velocidex.com/golang/go-pe => ../go-pe
