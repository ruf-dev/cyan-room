build:
	GOOS=linux GOARCH=amd64 go build -o cyan-room cmd/service/main.go

ship:
	scp cyan-room gullofin:/home/deployer/crp/cyan-room