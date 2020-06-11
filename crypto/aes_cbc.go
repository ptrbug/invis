package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

//AesEncryptCBC encrypt
func AesEncryptCBC(origData []byte, key []byte) (encrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	encrypted = make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted
}

//AesDecryptCBC decrypt
func AesDecryptCBC(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted = make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	return decrypted
}
