package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/services"
)

/*
Security Code Scanner
	In answering the code exercise, Golang is encouraged, but any high-level language will do.
	Description:
		Create a console application that mimics a security code scanner.
		The application [accepts path to the source code] and [scan configuration in the parameters], performs
		security analysis and prints report to output.

		[There are 3 types of security checks and adding the [additional types should be simple.]

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
*/

func main() {

	chQuit := make(chan os.Signal, 2)
	signal.Notify(chQuit, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for range chQuit {
			cancel()
			os.Exit(0)
		}
	}()

	var path string
	flag.StringVar(&path, "path", "", "file path to scan")

	var st int
	flag.IntVar(&st, "type", 0, "scan type:\n 0: full scan \n 1: cross site scripting \n 2: sensitive data exposure \n 3: cross sql injection")
	scanType := customtypes.ScanType(st)

	var outputFormat string
	flag.StringVar(&outputFormat, "format", "json", "output format json|text")

	flag.Parse()

	if len(path) == 0 {
		fmt.Println("Usage: securitycodescanner -path /path/to/scanner -type 0|1|2|3 -format json|text")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if scanType > customtypes.ScanTypeCrossSqlInjection {
		scanType = customtypes.ScanTypeFull
	}

	if outputFormat != "json" && outputFormat != "text" {
		log.Fatal("invalid output format: ", outputFormat)
	}

	s := spinner.New(spinner.CharSets[35], 800*time.Millisecond) // Build our new spinner

	fmt.Println("scanning path: ", path)
	fmt.Printf("scan type: ")

	switch scanType {
	case customtypes.ScanTypeFull:
		fmt.Printf("Full")
	case customtypes.ScanTypeCrossSiteScripting:
		fmt.Printf("Cross Site Scripting")
	case customtypes.ScanTypeSensitiveDataExposure:
		fmt.Printf("Sensitive Data Exposure")
	case customtypes.ScanTypeCrossSqlInjection:
		fmt.Printf("Cross Sql Injection")
	}

	fmt.Println("output format: ", outputFormat)
	fmt.Println("")

	s.Start()
	defer s.Stop()

	scanner := services.NewScannerService()
	scanResult, err := scanner.Execute(ctx, path, scanType)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(scanResult.StartAt)
	fmt.Println(scanResult.EndAt)

}
