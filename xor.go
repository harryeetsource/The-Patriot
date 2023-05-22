package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
)

func xorDecrypt(input []byte, key byte) []byte {
	output := make([]byte, len(input))
	for i := range input {
		output[i] = input[i] ^ key
	}
	return output
}

func main() {
	key := byte(0xFF)  // your key
	dirname := "."  // current directory

	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		fmt.Println("Failed to read directory:", err)
		return
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		filename := filepath.Join(dirname, file.Name())
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Printf("Failed to read file %s: %v\n", filename, err)
			continue
		}

		decryptedData := xorDecrypt(data, key)

		// Write decrypted data back to a new file with "_decrypted" appended to the name
		newFilename := filename + "_decrypted"
		err = ioutil.WriteFile(newFilename, decryptedData, file.Mode())
		if err != nil {
			fmt.Printf("Failed to write file %s: %v\n", newFilename, err)
		} else {
			fmt.Println("Decrypted data written to:", newFilename)
		}
	}
}
