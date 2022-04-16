# Task project demo

## Purpose
Security Code Scanner
In answering the code exercise, Golang is encouraged, but any high-level language will do.
Description:
Create a console application that mimics a security code scanner.
The application accepts path to the source code and scan configuration in the parameters, performs
security analysis and prints report to output.
There are 3 types of security checks and adding the additional types should be simple.
1) Cross site scripting
Check that there are no html or JavaScript files with following statement:
Alert()
2) Sensitive data exposure.
Check that there are no files with following strings on a same line:
“Checkmarx” “Hellman & Friedman” “$1.15b”
3) SQL injection
Check that there are no files
with statements starting with quotes, containing SELECT, WHERE, %s and ending with quotes
e.g. "…. SELECT …. WHERE …. %s …. "
There are 2 supported output formats and adding the additional formats should be simple.
1) Plain text with vulnerability per line e.g. [SQL injection] in file “DB.go” on line 45
2) Json representing the same information

## Dependencies
- Docker
- Docker Compose

## Getting Started

First create the db docker volume:
```bash
docker volume create --name=mysql_task_data
```

Now execute

```bash
make prepare-rabbitmq
```

then

```bash
make compose-up
```

This command will start all containers with docker-compose.

### open 3 consoles and run
```bash
make docker-exec
```

Now we are ready to start the application.

### For each console opened

### Start grpc server in new terminal
```bash
make run-grpc-server
```

### Start queue worker to read messages from rabbitMQ queue
```bash
make run-read-queue-worker
```

### Run client to create task
```bash
go run cmd/grpclient/main.go TASK_SUMMARY
```

## Make commands

### Running tests locally
```bash
make test
```
### Create mocks from interface
```bash
make mock
```

windows
```
path\go\bin\mockery.exe --all
```

### Gen proto files
```bash
make gen-proto
```

### Gen rpc files
```bash
make gen-rpc
```

## for more options open Makefile archive

## Example

![alt text](https://github.com/fgmaia/task/blob/master/how_to_test_console.png?raw=true)

## Some tests

![alt text](https://github.com/fgmaia/task/blob/master/how_to_test_console1.png?raw=true)