# Lighthouse


## Getting Started

Migrate configuration from DAS.

```
$ export STYRA_TOKEN=...
$ go run main.go migrate -u https://expo.styra.com/ > config.yaml
```

Launch the Lighthouse service.

```
go run main.go run
```