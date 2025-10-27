module github.com/Velocidex/etw

go 1.25

require (
	github.com/Microsoft/go-winio v0.5.0
	github.com/Velocidex/ordereddict v0.0.0-20250821063524-02dc06e46238
	github.com/Velocidex/ttlcache/v2 v2.9.1-0.20240517145123-a3f45e86e130
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.8.1
	golang.org/x/sys v0.37.0
	www.velocidex.com/golang/binparsergen v0.1.1-0.20240404114946-8f66c7cf586e
	www.velocidex.com/golang/go-pe v0.1.1-0.20250101153735-7a925ba8334b
)

require (
	github.com/Velocidex/json v0.0.0-20220224052537-92f3c0326e5a // indirect
	github.com/Velocidex/pkcs7 v0.0.0-20230220112103-d4ed02e1862a // indirect
	github.com/Velocidex/yaml/v2 v2.2.8 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.30.0 // indirect
)

// replace www.velocidex.com/golang/go-pe => ../go-pe
