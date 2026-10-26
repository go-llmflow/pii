module github.com/go-llmflow/pii/bench/presidiocmp

go 1.27.3

require (
	github.com/go-llmflow/pii v0.1.0
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

// The harness measures the pii of this checkout.
replace github.com/go-llmflow/pii => ../..
