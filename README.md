# SecurityCodeScanner Project demo

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


### Running locally
```bash
make run
```
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
