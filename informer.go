package main

import (
	"bufio"
	"flag"
	"fmt"
	"junjie.pro/informer/library"
	"os"
	"strings"
)

var (
	add        bool
	remove     bool
	update     bool
	query      string
	key        string
	list       bool
	showSecure bool
	flagSet    map[string]bool
	version    bool
)

func init() {
	flag.BoolVar(&add, "add", false, "Add secure")
	flag.BoolVar(&remove, "remove", false, "Delete secure")
	flag.BoolVar(&update, "update", false, "Update secure")
	flag.StringVar(&query, "query", "", "Query secure")
	flag.StringVar(&key, "key", "", "Key for encrypt/decrypt secures")
	flag.BoolVar(&list, "list", false, "List all secure")
	flag.BoolVar(&showSecure, "show-secure", false, "Show plain text secure")
	flag.BoolVar(&version, "version", false, "Show current version")
	flag.Parse()

	flagSet = map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagSet[f.Name] = true
	})
}

func main() {
	if len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}

	if version {
		fmt.Println("Informer 0.0.3")
		return
	}

	informerLibrary, err := library.ReadLibrary()
	if err != nil {
		panic(err)
	}

	if flagSet["add"] {
		if key == "" {
			panic("key is empty")
		}

		err := informerLibrary.Unlock([]byte(key))
		if err != nil {
			panic(err)
		}

		secure, err := inputSecureStore()
		informerLibrary.Add(secure)

		err = informerLibrary.Lock([]byte(key))
		if err != nil {
			panic(err)
		}

		err = informerLibrary.WriteLibrary()
		if err != nil {
			panic(err)
		}
	}

	if flagSet["remove"] {
		if key == "" {
			panic("key is empty")
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Println("Input information:")
		fmt.Print("id: ")
		id, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		id = strings.Trim(id, "\n")
		fmt.Print("platform: ")
		platform, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		platform = strings.Trim(platform, "\n")
		fmt.Print("username: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		username = strings.Trim(username, "\n")

		found, index := informerLibrary.QueryPrimaryKey(id, platform, username)
		if found {
			err := informerLibrary.Unlock([]byte(key))
			if err != nil {
				panic(err)
			}

			informerLibrary.Remove(index)

			err = informerLibrary.Lock([]byte(key))
			if err != nil {
				panic(err)
			}

			err = informerLibrary.WriteLibrary()
			if err != nil {
				panic(err)
			}

			return
		} else {
			fmt.Println("Not Found")
			return
		}
	}

	if flagSet["update"] {
		fmt.Print("Update which Secure? ")

		reader := bufio.NewReader(os.Stdin)

		fmt.Println("Input information:")
		fmt.Print("id: ")
		id, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		id = strings.Trim(id, "\n")
		fmt.Print("platform: ")
		platform, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		platform = strings.Trim(platform, "\n")
		fmt.Print("username: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		username = strings.Trim(username, "\n")

		found, index := informerLibrary.QueryPrimaryKey(id, platform, username)
		if found {
			newSecure, err := inputSecureStore()
			if err != nil {
				panic(err)
			}

			err = informerLibrary.Unlock([]byte(key))
			if err != nil {
				panic(err)
			}

			informerLibrary.Update(index, newSecure)

			err = informerLibrary.Lock([]byte(key))
			if err != nil {
				panic(err)
			}

			err = informerLibrary.WriteLibrary()
			if err != nil {
				panic(err)
			}

			return
		} else {
			fmt.Println("Not Found")
			return
		}
	}

	if flagSet["list"] {
		if showSecure {
			err := informerLibrary.Unlock([]byte(key))
			if err != nil {
				panic(err)
			}
		}

		for _, secure := range informerLibrary.List() {
			printSecureStore(secure, showSecure)
		}
	}

	if flagSet["query"] {
		found, secures := informerLibrary.Query(query)
		if found {
			for _, secure := range secures {
				printSecureStore(secure, showSecure)
			}
		}
	}
}

func printSecureStore(secure library.SecureStore, showSecure bool) {
	fmt.Println("id:", secure.ID)
	fmt.Println("platform:", secure.Platform)
	fmt.Println("friendly name:", secure.FriendlyName)
	fmt.Println("icon:", secure.Icon)
	fmt.Println("username:", secure.Username)

	if showSecure {
		fmt.Println("password:", secure.Password)
		fmt.Println("otp:", secure.OTP)
		fmt.Println("otp type:", secure.OTPType)
	}

	fmt.Println()
}

func inputSecureStore() (library.SecureStore, error) {
	reader := bufio.NewReader(os.Stdin)
	var id, platform, friendlyName, icon, username, password, otp, otpType string

	fmt.Println("Input information:")
	fmt.Print("id: ")
	id, err := reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	id = strings.Trim(id, "\n")
	fmt.Print("platform: ")
	platform, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	platform = strings.Trim(platform, "\n")
	fmt.Print("friendly name: ")
	friendlyName, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	friendlyName = strings.Trim(friendlyName, "\n")
	fmt.Print("icon: ")
	icon, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	icon = strings.Trim(icon, "\n")
	fmt.Print("username: ")
	username, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	username = strings.Trim(username, "\n")
	fmt.Print("password: ")
	password, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	password = strings.Trim(password, "\n")
	fmt.Print("otp: ")
	otp, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	otp = strings.Trim(otp, "\n")
	fmt.Print("otp type: ")
	otpType, err = reader.ReadString('\n')
	if err != nil {
		return library.SecureStore{}, err
	}
	otpType = strings.Trim(otpType, "\n")

	secure := library.SecureStore{
		ID:           id,
		Platform:     platform,
		FriendlyName: friendlyName,
		Icon:         icon,
		Username:     username,
		Password:     password,
		OTP:          otp,
		OTPType:      otpType,
	}

	return secure, err
}
