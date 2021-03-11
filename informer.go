package main

import (
	"bufio"
	"flag"
	"fmt"
	"junjie.pro/informer/api"
	"junjie.pro/informer/library"
	"os"
)

var (
	add        bool
	remove     bool
	update     bool
	query      string
	key        string
	list       bool
	showSecure bool
	server     bool
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
	flag.BoolVar(&server, "server", false, "Enable server mode")
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
		fmt.Println("Informer 0.0.8")
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

		secure := inputSecureStore()
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

		scanner := bufio.NewScanner(os.Stdin)

		fmt.Println("Input information:")

		fmt.Print("id: ")
		scanner.Scan()
		id := scanner.Text()

		fmt.Print("platform: ")
		scanner.Scan()
		platform := scanner.Text()

		fmt.Print("username: ")
		scanner.Scan()
		username := scanner.Text()

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

		scanner := bufio.NewScanner(os.Stdin)

		fmt.Println("Input information:")

		fmt.Print("id: ")
		scanner.Scan()
		id := scanner.Text()

		fmt.Print("platform: ")
		scanner.Scan()
		platform := scanner.Text()

		fmt.Print("username: ")
		scanner.Scan()
		username := scanner.Text()

		found, index := informerLibrary.QueryPrimaryKey(id, platform, username)
		if found {
			newSecure := inputSecureStore()

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

	if flagSet["server"] {
		api.Serve()
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

func inputSecureStore() library.SecureStore {
	scanner := bufio.NewScanner(os.Stdin)
	var id, platform, friendlyName, icon, username, password, otp, otpType string

	fmt.Println("Input information:")

	fmt.Print("id: ")
	scanner.Scan()
	id = scanner.Text()

	fmt.Print("platform: ")
	scanner.Scan()
	platform = scanner.Text()

	fmt.Print("friendly name: ")
	scanner.Scan()
	friendlyName = scanner.Text()

	fmt.Print("icon: ")
	scanner.Scan()
	icon = scanner.Text()

	fmt.Print("username: ")
	scanner.Scan()
	username = scanner.Text()

	fmt.Print("password: ")
	scanner.Scan()
	password = scanner.Text()

	fmt.Print("otp: ")
	scanner.Scan()
	otp = scanner.Text()

	fmt.Print("otp type: ")
	scanner.Scan()
	otpType = scanner.Text()

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

	return secure
}
