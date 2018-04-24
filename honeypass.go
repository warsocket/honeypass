package main
import "net"
import "os"
import "fmt"
import "time"
import "bufio"
import "io/ioutil"
import "regexp"
import "log"
import "strings"
import "encoding/base64"
import "crypto/tls"
import "golang.org/x/crypto/ssh"
import "path/filepath"


const MaxInt = int(^uint(0)  >> 1) 

var hostname string = "example.com"
var defTlsConfig *tls.Config
var sshConfig *ssh.ServerConfig



func TcpHandler(listenaddress string, handleFunc func(net.Conn)){
	listen, err := net.Listen("tcp", listenaddress)
	if err != nil {
		log.Fatal(fmt.Sprintf("TCP Error Listening at %s", listenaddress))
		return
	}

    defer listen.Close()
    for{
        conn ,_ := listen.Accept()
        go handleFunc(conn)
    }

}


func TcpTlsHandler(listenaddress string, handleFunc func(net.Conn), tlsConfig *tls.Config){
    listen, err := net.Listen("tcp", listenaddress)
    if err != nil {
        log.Fatal(fmt.Sprintf("TLS Error Listening at %s", listenaddress))
        return
    }

    defer listen.Close()
    for{
        conn ,_ := listen.Accept()
        tlsconn := tls.Server(conn, tlsConfig)       
        go handleFunc(tlsconn)
    }
}


func main(){
	//set hostname for various protocols
	if len(os.Args) > 1 {
		hostname = os.Args[1]
	}

	//init TLS config
    cer, err := tls.LoadX509KeyPair("/etc/ssl/certs/ssl-cert-snakeoil.pem", "/etc/ssl/private/ssl-cert-snakeoil.key")
    if err != nil {
        log.Println(err)
    }
    defTlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
    defTlsConfig = defTlsConfig //prevents not used message so you can easlily make a config without using TLS


    //init SSH config
    sshConfig = &ssh.ServerConfig{
    	MaxAuthTries: MaxInt,
	    PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	    	fmt.Printf("%s:%s\r\n", c.User(), string(pass))
	    	return nil, fmt.Errorf("password rejected for %q", c.User())
	    },
	}

	privKey := filepath.Join(os.Getenv("HOME"),"/.ssh/id_rsa")
	privateBytes, err := ioutil.ReadFile(privKey)
	if err != nil {
	    log.Println("Failed to load SSH private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
	    log.Println("Failed to parse SSH private key: ", err)
	}

	sshConfig.AddHostKey(private)


    //Start handlers

	//SSH
	go TcpHandler("0.0.0.0:22", handleSsh)

    //HTTP
	go TcpHandler("0.0.0.0:80", handleHttp)
    go TcpTlsHandler("0.0.0.0:443", handleHttp, defTlsConfig)

    //(E)SMTP
	go TcpHandler("0.0.0.0:25", handleSmtp)
	go TcpHandler("0.0.0.0:587", handleSmtp) //submission, but the handler works for smtp and submission.
    go TcpTlsHandler("0.0.0.0:465", handleSmtp, defTlsConfig) //deprecated port, but if ppl put passwords in well take it.

    //IMAP
    go TcpHandler("0.0.0.0:143", handleImap)
    go TcpTlsHandler("0.0.0.0:993", handleImap, defTlsConfig)

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
				fmt.Println(string(decoded))
			}

		}
		if len(msg) < 1 {break}
	}

	fmt.Fprint(writer, `HTTP/1.1 401 Unauthorized
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
						fmt.Println( userpassPlain[1:] + "\n" )
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


func handleImap(conn net.Conn){
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	fmt.Fprint(writer, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] Honeypot ready.\r\n") //We need to add STARTTLS later here when implementing starttls
	writer.Flush()
	
	for{
		fullcmd, _, err := reader.ReadLine()
		if err != nil {break}

		cmd := strings.Split(string(fullcmd), " ")

		//substitute no identifier for *
		if cmd[0] == "" {
			cmd[0] = "*"
		}

		if len(cmd) < 2{
			fmt.Fprintf(writer, "%s BAD Error in IMAP command received by server.\r\n", cmd[0])
			writer.Flush()
			continue
		}

		cmdId, cmdCmd, cmdRest := cmd[0], strings.ToUpper(cmd[1]), cmd[2:]
		cmdId = cmdId
		cmdCmd = cmdCmd
		cmdRest = cmdRest

		if cmdCmd == "CAPABILITY"{
			fmt.Fprintf(writer, "%s CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n", cmdId) //We need to add STARTTLS later here when implementing starttls

		} else if cmdCmd == "LOGIN"{
			fmt.Fprintf(writer, "%s NO [AUTHENTICATIONFAILED] Authentication failed.\r\n", cmdId)

			if len(cmdRest) >= 2{
				user, pass := cmdRest[0], cmdRest[1]

				if user[0] == '"' && user[len(user)-1] == '"'{
					user = user[1:len(user)-1]
				}

				if pass[0] == '"' && pass[len(pass)-1] == '"'{
					pass = pass[1:len(pass)-1]
				}

				fmt.Printf("%s:%s\n", user, pass)
			}

		} else {
			fmt.Fprintf(writer, "%s BAD Error in IMAP command received by server.\r\n", cmdId)
		}

		writer.Flush()
	}

}

func handleSsh(conn net.Conn){
	ssh.NewServerConn(conn, sshConfig)
	conn.Close()
}
