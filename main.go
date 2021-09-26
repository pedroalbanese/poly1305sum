package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/poly1305"
)

var (
	check     = flag.String("c", "", "Check hashsum file.")
	key       = flag.String("k", "", "Secret key.")
	recursive = flag.Bool("r", false, "Process directories recursively.")
	target    = flag.String("t", "", "Target file/wildcard to generate hashsum list.")
	verbose   = flag.Bool("v", false, "Verbose mode. (for CHECK command)")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Println("Poly1305 Hashsum Tool - ALBANESE Lab (c) 2020-2022\n")
		fmt.Println("Usage of", os.Args[0]+":")
		fmt.Printf("%s [-v] [-c <hash.ext>] -key $SecretKey -t <file.ext>\n\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *target != "" && *recursive == false {
		files, err := filepath.Glob(*target)
		if err != nil {
			log.Fatal(err)
		}
		for _, match := range files {
			var keyx [32]byte
			copy(keyx[:], []byte(*key))
			h := poly1305.New(&keyx)
			f, err := os.Open(match)
			if err != nil {
				log.Fatal(err)
			}
			file, err := os.Stat(match)
			if file.IsDir() {
			} else {
				if _, err := io.Copy(h, f); err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
			}
			f.Close()
		}
	}

	if *target != "" && *recursive == true {
		err := filepath.Walk(filepath.Dir(*target),
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				file, err := os.Stat(path)
				if file.IsDir() {
				} else {
					filename := filepath.Base(path)
					pattern := filepath.Base(*target)
					matched, err := filepath.Match(pattern, filename)
					if err != nil {
						fmt.Println(err)
					}
					if matched {
						var keyx [32]byte
						copy(keyx[:], []byte(*key))
						h := poly1305.New(&keyx)
						f, err := os.Open(path)
						if err != nil {
							log.Fatal(err)
						}
						if _, err := io.Copy(h, f); err != nil {
							log.Fatal(err)
						}
						f.Close()
						fmt.Println(hex.EncodeToString(h.Sum(nil)), "*"+f.Name())
					}
				}
				return nil
			})
		if err != nil {
			log.Println(err)
		}
	}

	if *check != "" {
		var file io.Reader
		var err error
		if *check == "-" {
			file = os.Stdin
		} else {
			file, err = os.Open(*check)
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}
		}
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		var txtlines []string
		for scanner.Scan() {
			txtlines = append(txtlines, scanner.Text())
		}
		for _, eachline := range txtlines {
			lines := strings.Split(string(eachline), " *")
			if strings.Contains(string(eachline), " *") {
				var keyx [32]byte
				copy(keyx[:], []byte(*key))
				h := poly1305.New(&keyx)
				_, err := os.Stat(lines[1])
				if err == nil {
					f, err := os.Open(lines[1])
					if err != nil {
						log.Fatal(err)
					}
					io.Copy(h, f)
					f.Close()

					if *verbose {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
							fmt.Println(lines[1]+"\t", "OK")
						} else {
							fmt.Println(lines[1]+"\t", "FAILED")
						}
					} else {
						if hex.EncodeToString(h.Sum(nil)) == lines[0] {
						} else {
							os.Exit(1)
						}
					}
				} else {
					if *verbose {
						fmt.Println(lines[1]+"\t", "Not found!")
					} else {
						os.Exit(1)
					}
				}
			}
		}
	}
}
