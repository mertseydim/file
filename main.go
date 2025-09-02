package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	_ "github.com/joho/godotenv/autoload"
)

var db *sql.DB

func main() {
	app := fiber.New()
	app.Use(logger.New())

	app.Static("/", "./public")

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})

	app.Post("/upload", uploadFile)

	app.Get("/download/:link", downloadFile)

	initDB()

	log.Fatal(app.Listen(":3000"))
}

func initDB() {
	config := mysql.Config{
		User:   "root",
		Passwd: "190732Mert",
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "file_transfer_db",
	}
	var err error
	db, err = sql.Open("mysql", config.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func uploadFile(c *fiber.Ctx) error {
	sender := c.FormValue("sender")
	receiver := c.FormValue("receiver")
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).SendString("Dosya yüklenemedi")
	}
	if file.Size > 1024*1024*1024 {
		return c.Status(400).SendString("Dosya 1GB'dan büyük")
	}
	link := uuid.New().String()
	dir := "./uploads"
	os.MkdirAll(dir, os.ModePerm)
	path := filepath.Join(dir, link+"_"+file.Filename)
	c.SaveFile(file, path)
	_, err = db.Exec("INSERT INTO files (sender_email, receiver_email, file_name, file_path, download_link) VALUES (?, ?, ?, ?, ?)",
		sender, receiver, file.Filename, path, link)
	if err != nil {
		return c.Status(500).SendString("Veritabanı hatası")
	}
	sendEmail(receiver, sender, file.Filename, fmt.Sprintf("https://mertseydim.com.tr/download/%s", link))
	return c.SendString("Dosya yüklendi ve link gönderildi")
}

func downloadFile(c *fiber.Ctx) error {
	link := c.Params("link")
	var path, name string
	err := db.QueryRow("SELECT file_path, file_name FROM files WHERE download_link = ?", link).Scan(&path, &name)
	if err != nil {
		return c.Status(404).SendString("Dosya bulunamadı")
	}
	file, err := os.Open(path)
	if err != nil {
		return c.Status(500).SendString("Dosya açma hatası")
	}
	defer file.Close()
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	c.Set("Content-Type", "application/octet-stream")
	_, err = io.Copy(c.Response().BodyWriter(), file)
	if err != nil {
		return err
	}
	return nil
}

func sendEmail(to, from, filename, link string) {
	apiKey := os.Getenv("TOKEN")
	if apiKey == "" {
		log.Println("SENDGRID_API_KEY ortam değişkeni ayarlanmadı")
		return
	}

	fromEmail := mail.NewEmail("Gönderen", from)
	toEmail := mail.NewEmail("Alıcı", to)
	subject := "Yeni Dosya Transferi"
	plainTextContent := fmt.Sprintf("Merhaba, %s size %s dosyasını gönderdi. İndirmek için: %s", from, filename, link)
	htmlContent := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="tr">
	<head>
		<meta charset="UTF-8">
		<style>
			body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
			.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: auto; }
			h2 { color: #007bff; }
			p { margin: 10px 0; }
			a { display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
			a:hover { background-color: #0056b3; }
		</style>
	</head>
	<body>
		<div class="container">
			<h2>Yeni Dosya Transferi</h2>
			<p>Merhaba,</p>
			<p>%s size <strong>%s</strong> dosyasını gönderdi.</p>
			<p>İndirmek için aşağıdaki bağlantıya tıklayın:</p>
			<a href="%s">Dosyayı İndir</a>
		</div>
	</body>
	</html>`, from, filename, link)

	message := mail.NewSingleEmail(fromEmail, subject, toEmail, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(apiKey)
	response, err := client.Send(message)
	if err != nil {
		log.Println("Email gönderme hatası:", err)
	} else if response.StatusCode != http.StatusAccepted {
		log.Printf("Email gönderme başarısız: %d - %s\n", response.StatusCode, response.Body)
	}
}
