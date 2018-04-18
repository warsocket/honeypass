package main
import "net"
import "os"
import "fmt"
import "time"
import "bufio"
import "regexp"
import "log"
import "strings"
import "encoding/base64"


var hostname string = "example.com"

func TcpHandler(listenaddress string, handleFunc func(net.Conn)){
	listen, err := net.Listen("tcp", listenaddress)
	if err != nil {
		log.Fatal("Error Listening")
		return
	}

	defer listen.Close()

	for{
		conn ,_ := listen.Accept()
		if err == nil{
			handleFunc(conn)	
		}else{
			log.Println("Error Acepting")
		}
		
	}
}

func main(){
	if len(os.Args) > 1 {
		hostname = os.Args[1]
	}

	go TcpHandler("0.0.0.0:80", handleHttp)
	go TcpHandler("0.0.0.0:25", handleSmtp)
	go TcpHandler("0.0.0.0:587", handleSmtp) //submission, but the handler works for smtp and submission

	for{
		time.Sleep(1)
	}
}

func handleHttp(conn net.Conn){
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	re, _ := regexp.Compile("^Authorization: Basic (.*)$")

	//Read until end of request
	for{
		msg, _, _ := reader.ReadLine()

		found := re.FindStringSubmatch(string(msg))
		if found != nil {
			decoded, err := base64.StdEncoding.DecodeString(found[1])
			if err == nil{
				print(string(decoded) + "\n")
			}

		}
		if len(msg) < 1 {break}
	}

	writer.WriteString(`HTTP/1.1 401 Unauthorized
Server: Honeypot
WWW-Authenticate: Basic realm="Hive"
Connection: Close

`)
	writer.Flush()
	conn.Close()
}

func handleSmtp(conn net.Conn){
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	fmt.Fprintf(writer, "220 %s ESMTP Honeypot\r\n", hostname)
	writer.Flush()

	// nuke := func(){
	// 	writer.WriteString("550 Bzzz, *stings*\r\n")
	// 	writer.Flush()
	// 	conn.Close()
	// 	return
	// }

	// Stateless command processing
	// We allow way more abuse/erros then the RFC's, we dont care, we need passwords.
	for{
		fullcmd, _, err := reader.ReadLine()
		if err != nil {break}

		if len(fullcmd) < 4 {
			fmt.Fprintf(writer, "502 5.5.2 Error: command not recognized\r\n")
			writer.Flush()
			continue
		}
		cmd := strings.ToUpper(string(fullcmd[:4]))

		if cmd == "HELO"{
			fmt.Fprintf(writer, "250 %s\r\n", hostname)

		} else if cmd == "EHLO" {
			fmt.Fprintf(writer, "250-%s\r\n", hostname)
			fmt.Fprintf(writer, "250 AUTH PLAIN\r\n")

		} else if cmd == "MAIL" {
			fmt.Fprintf(writer, "250 2.1.0 Ok\r\n")

		} else if cmd == "RCPT" {
			fmt.Fprintf(writer, "554 5.7.1 Error: Relay access denied\r\n")

		} else if cmd == "AUTH" {
			matched, _ := regexp.MatchString("^AUTH PLAIN\\s*$", strings.ToUpper(string(fullcmd)))
			if matched { //bit of state needed here
				fmt.Fprintf(writer, "334\r\n")
				writer.Flush()

				userpass, _, err := reader.ReadLine()
				if err != nil {break}

				decoded, err := base64.StdEncoding.DecodeString(string(userpass))
				if err == nil{
					userpassPlain := strings.Replace(string(decoded),"\x00",":",-1)
					if len(userpassPlain) > 0{
						print( userpassPlain[1:] + "\n")
					}
				}
				fmt.Fprintf(writer, "535 5.7.8 Error: authentication failed\r\n")

			} else {
				fmt.Fprintf(writer, "535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n")
			}	

		} else {
			fmt.Fprintf(writer, "502 5.5.2 Error: command not recognized\r\n")
		}

		writer.Flush()
	}
	

}