# Integration test suite

This package contains public-API integration, end-to-end, regression, and
benchmark tests. Run it with:

```sh
go test ./test
go test -race ./test
go test -bench=. ./test
```

White-box unit tests and fuzz targets that need unexported implementation
details remain beside the `xhttp` package. Go only permits same-package tests
to access those details, and exporting internals solely to move tests here
would weaken the library API.
