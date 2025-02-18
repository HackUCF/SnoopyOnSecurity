package main

import (
	"log"

	"golang.org/x/crypto/ssh"
	"github.com/bramvdbogaerde/go-scp"
	"os"
	"context"
)

func copy_zip(client *ssh.Client) {
	scpsession, _ := scp.NewClientBySSH(client)
	f, _ := os.Open(os.Args[4])

	defer scpsession.Close()
	defer f.Close()

	err := scpsession.CopyFromFile(context.Background(), *f, os.Args[4], "0655")
	if err != nil {
		log.Printf("Failed to run command on: %v\n", err)
		return
	}

}
