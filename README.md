# Lighthouse


## Getting Started

Export configuration from DAS.

```
$ export STYRA_TOKEN=...
$ go run tools/export/export.go -u https://expo.styra.com/ > config.yaml
```

Launch the Lighthouse service.

```
go run main.go run
```