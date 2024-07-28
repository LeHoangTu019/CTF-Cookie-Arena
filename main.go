package main


// Các thư viện chuẩn của Go ( Go (Golang) là ngôn ngữ lập trình mở của Google)
import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"


	//Thư viện gin, 1 framework nhẹ để xây dựng các dịch vụ web trong Go
	"github.com/gin-gonic/gin"
)

// Hàm kiểm tra chuyển hướng và trả về lỗi nếu: (1) Số lần chuyển hướng lớn 2 hoặc địa chỉ IP cuối cùng khác 127.0.0.1 (127.0.0.1 là máy chủ - host)
// Suy lận rằng đây thuộc 1 dạng lỗi SSRF (Server-Side request Furgery) => giả mạo gói tin đưa cho chính server xử lý

func redirectChecker(req *http.Request, via []*http.Request) error {
	reqIp := strings.Split(via[len(via)-1].Host, ":")[0]

	if len(via) >= 2 || reqIp != "127.0.0.1" {
		return errors.New("Something wrong")
	}

	return nil
}

func main() {

	// Đọc file /flag.txt và lưu nội dung vào biến flag
	flag, err := os.ReadFile("/flag.txt")
	if err != nil {
		panic(err)
	}

	r := gin.Default() // Khởi tạo một router mặc định của Gin

	r.LoadHTMLGlob("view/*.html") // Tải tất cả các file HTML trong thư mục view
	r.Static("/static", "./static") // Đặt thư mục tĩnh để phục vụ các tài nguyên tĩnh như CSS, JS

	// Định nghĩa route cho phương thức GET tại endpoint "/"
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"a": c.ClientIP(), // Trả về địa chỉ IP của client trong HTML
		})
	})

	r.GET("/curl/", func(c *gin.Context) {
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return redirectChecker(req, via)
			},
		}

		reqUrl := strings.ToLower(c.Query("url")) // Lấy URL từ query parameter và chuyển thành chữ thường
		reqHeaderKey := c.Query("header_key") // Lấy giá trị header_key từ query parameter
		reqHeaderValue := c.Query("header_value") // Lấy giá trị header_value từ query parameter
		reqIP := strings.Split(c.Request.RemoteAddr, ":")[0] // Lấy địa chỉ IP của client từ RemoteAddr
		fmt.Println("[+] " + reqUrl + ", " + reqIP + ", " + reqHeaderKey + ", " + reqHeaderValue)

		//Kiểm tra điều kiện IP có phải từ 127.0.0.1 và trong chuỗi có chứa các kí tự "flag, curl, %" không

		if c.ClientIP() != "127.0.0.1" && (strings.Contains(reqUrl, "flag") || strings.Contains(reqUrl, "curl") || strings.Contains(reqUrl, "%")) {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Something wrong"})
			return
		}

		// Tạo yêu cầu HTTP GET mới với URL đã giải mã
		req, err := http.NewRequest("GET", reqUrl, nil)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Something wrong"})
			return
		}

		// Nếu có giá trị header_key và header_value, đặt chúng vào header của yêu cầu
		if reqHeaderKey != "" || reqHeaderValue != "" {
			req.Header.Set(reqHeaderKey, reqHeaderValue)
		}

		// Thực hiện yêu cầu HTTP
		resp, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Something wrong"})
			return
		}

		defer resp.Body.Close()

		// Đọc nội dung của phản hồi
		bodyText, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Something wrong"})
			return
		}
		statusText := resp.Status

		// Trả về phản hồi dưới dạng JSON
		c.JSON(http.StatusOK, gin.H{
			"body":   string(bodyText),
			"status": statusText,
		})
	})

	// Định nghĩa route cho phương thức GET tại endpoint "/flag/"
	r.GET("/flag/", func(c *gin.Context) {
		reqIP := strings.Split(c.Request.RemoteAddr, ":")[0]

		log.Println("[+] IP : " + reqIP)

		// Nếu IP là 127.0.0.1, trả về nội dung của flag
		if reqIP == "127.0.0.1" {
			c.JSON(http.StatusOK, gin.H{
				"message": flag,
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"message": "You are a Guest, This is only for Host",
		})
	})

	r.Run("0.0.0.0:1337")
}
