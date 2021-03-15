package api

import (
	"fmt"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	fmt.Println(GeneratePassword(16))
}
