package main
import "net"
// import "os"
import "time"
import "bufio"
import "regexp"
// import "strings"
import "encoding/base64"

func TcpHandler(listenaddress string){
	listen, err := net.Listen("tcp", listenaddress)
	if err != nil {
		print("Error Listening\n")
		return
	}

	defer listen.Close()

	for{
		conn ,_ := listen.Accept()
		if err == nil{
			handle(conn)	
		}else{
			print("Error Accpeting\n")
		}
		
	}
}



func main(){
	go TcpHandler("0.0.0.0:80")

	for{
		time.Sleep(1)
	}
}



func handle(conn net.Conn){
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
WWW-Authenticate: Basic realm=""
Connection: Close

`)
	writer.Flush()

	conn.Close()
}