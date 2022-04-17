package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fgmaia/securitycodescanner/internal/customtypes"
	"github.com/fgmaia/securitycodescanner/internal/filesearch"
	"github.com/fgmaia/securitycodescanner/internal/scanners"
	"github.com/fgmaia/securitycodescanner/internal/serializers"
	"github.com/fgmaia/securitycodescanner/internal/services"
)

type CodeScanner struct {
	Path         string
	ScanType     customtypes.ScanType
	Scans        []scanners.Scan
	OutputFormat string
}

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

	codeScanner := loadParams()
	start(ctx, codeScanner)
}

func loadParams() CodeScanner {
	codeScanner := CodeScanner{}

	flag.StringVar(&codeScanner.Path, "path", "", "file path to scan")

	var st int
	flag.IntVar(&st, "type", 0, "scan type:\n 0: full scan \n 1: cross site scripting \n 2: sensitive data exposure \n 3: cross sql injection")
	codeScanner.ScanType = customtypes.ScanType(st)

	flag.StringVar(&codeScanner.OutputFormat, "format", "json", "output format json|text")

	flag.Parse()

	if len(codeScanner.Path) == 0 {
		fmt.Println("Usage: securitycodescanner -path /path/to/scanner -type 0|1|2|3 -format json|text")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if codeScanner.ScanType > customtypes.ScanTypeSqlInjection {
		codeScanner.ScanType = customtypes.ScanTypeFull
	}

	if codeScanner.OutputFormat != "json" && codeScanner.OutputFormat != "text" {
		log.Fatal("invalid output format: ", codeScanner.OutputFormat)
	}

	fmt.Println("scanning path: ", codeScanner.Path)
	fmt.Printf("scan type: ")

	scans := make([]scanners.Scan, 0, 1)

	switch codeScanner.ScanType {
	case customtypes.ScanTypeFull:
		fmt.Printf("Full")
		scans = append(scans, scanners.NewCrossSiteScriptScan())
		scans = append(scans, scanners.NewSensitiveDataExposureScan())
		scans = append(scans, scanners.NewSqlInjection())

	case customtypes.ScanTypeCrossSiteScripting:
		fmt.Printf("Cross Site Scripting")
		scans = append(scans, scanners.NewCrossSiteScriptScan())

	case customtypes.ScanTypeSensitiveDataExposure:
		fmt.Printf("Sensitive Data Exposure")
		scans = append(scans, scanners.NewSensitiveDataExposureScan())

	case customtypes.ScanTypeSqlInjection:
		fmt.Printf("Cross Sql Injection")
		scans = append(scans, scanners.NewSqlInjection())
	}

	codeScanner.Scans = scans

	fmt.Println("")
	fmt.Println("output format: ", codeScanner.OutputFormat)
	fmt.Println("")

	return codeScanner
}

func start(ctx context.Context, codeScanner CodeScanner) {
	fileSearch := filesearch.NewFileSearch(50)
	scanner := services.NewScannerService(fileSearch, 20, codeScanner.ScanType, codeScanner.Scans...)

	scanResult, err := scanner.Execute(ctx, codeScanner.Path)
	if err != nil {
		log.Fatal(err)
	}

	var serializer serializers.Serializer
	var file string
	if codeScanner.OutputFormat == "json" {
		serializer = serializers.NewResultJson()
		file = "result.json"
	} else if codeScanner.OutputFormat == "text" {
		serializer = serializers.NewResultText()
		file = "result.txt"
	}

	fmt.Println("------------------------")
	fmt.Println("Path: ", scanResult.Path)
	fmt.Println("Files Scanned: ", scanResult.TotalScannedFiles)
	fmt.Println("Vulnerabilities Found: ", scanResult.VulnerabilitiesFound)
	fmt.Println(scanResult.StartAt)
	fmt.Println(scanResult.EndAt)
	fmt.Println("Result File: ", file)
	fmt.Println("------------------------")

	err = serializer.Execute(ctx, scanResult, file)

	if err != nil {
		log.Fatal(err)
	}

}
