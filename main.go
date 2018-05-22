package main

import (
	"context"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"github.com/Elbandi/gsync"
)

var (
	sourcefilePath = flag.String("file", "", "File path for base file, REQUIRED ")
	infilePath     = flag.String("in", "", "File path for input file")
	outfilePath    = flag.String("out", "", "File path for output file")
	debug          = flag.Bool("debug", false, "debug mode")
	blockSize      = flag.Int64("blocksize", 6*1024, "Block Size, default block size is 6KB")
)

func generateFingerprint(ctx context.Context) {
	srcFile, err := os.Open(*sourcefilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer srcFile.Close()

	fpFile, err := os.Create(*sourcefilePath + ".fingerprint")
	if err != nil {
		log.Fatal(err)
	}
	defer fpFile.Close()

	enc := gob.NewEncoder(fpFile)
	sigsCh, err := gsync.Signatures(ctx, srcFile, nil)
	for c := range sigsCh {
		select {
		case <-ctx.Done():
			os.Remove(fpFile.Name())
			log.Fatalln("godelta: checksum error: %#v\n", ctx.Err())
		default:
			break
		}

		if c.Error != nil {
			os.Remove(fpFile.Name())
			log.Fatalf("godelta: checksum error: %#v\n", c.Error)
		}

		if *debug {
			log.Printf("chunk %05d: %08x, %s", c.Index, c.Weak, hex.EncodeToString(c.Strong))
		}
		err = enc.Encode(c)
		if err != nil {
			os.Remove(fpFile.Name())
			log.Fatalf("godelta: checksum error: %#v\n", err)
		}
	}
}

func makeDiff(ctx context.Context) {
	fpFile, err := os.Open(*sourcefilePath + ".fingerprint")
	if err != nil {
		log.Fatal(err)
	}
	defer fpFile.Close()

	fpDecoder := gob.NewDecoder(fpFile)
	sigsCh := make(chan gsync.BlockSignature)
	go func() {
		defer close(sigsCh)

		for {
			// Allow for cancellation
			select {
			case <-ctx.Done():
				sigsCh <- gsync.BlockSignature{
					Index: 0,
					Error: ctx.Err(),
				}
				return
			default:
				// break out of the select block and continue reading
				break
			}
			var b gsync.BlockSignature
			err := fpDecoder.Decode(&b)
			if err == io.EOF {
				break
			}
			if err != nil {
				sigsCh <- gsync.BlockSignature{
					Index: b.Index,
					Error: err,
				}
				return
			}
			sigsCh <- b
		}
	}()
	if *debug {
		log.Println("Create lookup table")
	}
	cacheSigs, err := gsync.LookUpTable(ctx, sigsCh)
	if *debug {
		log.Println("Lookup table loaded")
	}

	var inFile, outFile *os.File
	if *infilePath != "" {
		inFile, err = os.Open(*infilePath)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer inFile.Close()
	} else {
		inFile = os.Stdin
	}

	if *outfilePath != "" {
		outFile, err = os.Create(*outfilePath)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}
	opsCh, err := gsync.Sync(ctx, inFile, nil, cacheSigs)

	enc := gob.NewEncoder(outFile)
	index := uint64(0)
	for o := range opsCh {
		select {
		case <-ctx.Done():
			if *outfilePath != "" {
				os.Remove(*outfilePath)
			}
			log.Fatalln(ctx.Err())
		default:
			break
		}

		if o.Error != nil {
			if *outfilePath != "" {
				os.Remove(*outfilePath)
			}
			log.Fatalf("godelta: patch error: %#v\n", o.Error)
		}
		if *debug {
			log.Printf("chunk %20d: %d / %d", index, o.Index, len(o.Data))
		}
		err = enc.Encode(o)
		if err != nil {
			if *outfilePath != "" {
				os.Remove(*outfilePath)
			}
			log.Fatalf("godelta: patch error: %#v\n", err)
		}
		index++
	}
}

func applyPatch(ctx context.Context) {
	srcFile, err := os.Open(*sourcefilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer srcFile.Close()

	var inFile, outFile *os.File
	if *infilePath != "" {
		inFile, err = os.Open(*infilePath)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer inFile.Close()
	} else {
		inFile = os.Stdin
	}
	if *outfilePath != "" {
		outFile, err = os.Create(*outfilePath)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}

	opsDecoder := gob.NewDecoder(inFile)
	opsCh := make(chan gsync.BlockOperation)
	go func() {
		defer close(opsCh)

		for {
			// Allow for cancellation
			select {
			case <-ctx.Done():
				opsCh <- gsync.BlockOperation{
					Error: ctx.Err(),
				}
				return
			default:
				// break out of the select block and continue reading
				break
			}
			var o gsync.BlockOperation
			err := opsDecoder.Decode(&o)
			if err == io.EOF {
				break
			}
			if err != nil {
				opsCh <- gsync.BlockOperation{
					Error: err,
				}
				return
			}
			opsCh <- o
		}
	}()
	err = gsync.Apply(ctx, outFile, srcFile, opsCh)
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	if *sourcefilePath == "" {
		fmt.Println("Missing File parameter")
		flag.Usage()
		return
	}
	if *blockSize < 1024 {
		fmt.Println("Invalid block size, must be more than 1024")
		flag.Usage()
		return
	}
	gsync.BlockSize = *blockSize

	//ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch flag.Arg(0) {
	case "fpgen":
		generateFingerprint(ctx)
	case "diff":
		if s, err := os.Stat(*sourcefilePath + ".fingerprint"); os.IsNotExist(err) || s.Size() < 1 {
			generateFingerprint(ctx)
		}
		makeDiff(ctx)
	case "patch":
		if _, err := os.Stat(*sourcefilePath); os.IsNotExist(err) {
			log.Fatalln("Base file is not exists")
		}
		if s, err := os.Stat(*sourcefilePath + ".fingerprint"); os.IsNotExist(err) || s.Size() < 1 {
			log.Fatalln("Fingerprint file is not exists")
		}
		applyPatch(ctx)
	default:
		log.Fatal("You must specify one of the following action: 'fpgen', 'diff' or 'patch'.")
	}
}
