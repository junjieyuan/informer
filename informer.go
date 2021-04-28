package main

import (
	"bufio"
	"flag"
	"fmt"
	"junjie.pro/informer/api"
	"junjie.pro/informer/library"
	"log"
	"os"
	"strconv"
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
		fmt.Println("Informer 0.2.0")
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
		scanner := bufio.NewScanner(os.Stdin)

		fmt.Println("Which secure do you want to remove?")
		fmt.Println()

		numberMapper := map[int64]string{}
		var i int64 = 0
		for k, v := range informerLibrary.SecureStore {
			elements := []string{strconv.FormatInt(i, 10), v.ID, v.Username}
			fmt.Println(strings.Join(elements, ", "))
			numberMapper[i] = k
			i++
		}

		fmt.Println()
		fmt.Print("number: ")
		scanner.Scan()
		id := scanner.Text()
		num, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			log.Println(err.Error())
		}

		if num >= 0 {
			informerLibrary.Remove(numberMapper[num])

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
		scanner := bufio.NewScanner(os.Stdin)

		fmt.Println("Which secure do you want to update?")
		fmt.Println()

		numberMapper := map[int64]string{}
		var i int64 = 0
		for k, v := range informerLibrary.SecureStore {
			elements := []string{strconv.FormatInt(i, 10), v.ID, v.Username}
			fmt.Println(strings.Join(elements, ", "))
			numberMapper[i] = k
			i++
		}

		fmt.Println()
		fmt.Print("number: ")
		scanner.Scan()
		id := scanner.Text()
		num, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			log.Println(err.Error())
		}

		if num >= 0 {
			newSecure := inputSecureStore()

			err = informerLibrary.Unlock([]byte(key))
			if err != nil {
				panic(err)
			}

			informerLibrary.Update(numberMapper[num], newSecure)

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
		if showSecure && key != "" {
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
		if showSecure && key != "" {
			err := informerLibrary.Unlock([]byte(key))
			if err != nil {
				log.Println(err.Error())
			}
		}

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
	var id, platform, friendlyName, username, password, otp, otpType string

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
		Username:     username,
		Password:     password,
		OTP:          otp,
		OTPType:      otpType,
	}

	return secure
}
