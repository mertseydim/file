package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/smtp"
	"os"
	"path/filepath"

	"github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/google/uuid"
	"github.com/jordan-wright/email"
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
	sendEmail(receiver, sender, file.Filename, fmt.Sprintf("http://localhost:3000/download/%s", link))
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
	e := email.NewEmail()
	e.From = from
	e.To = []string{to}
	e.Subject = "Yeni Dosya Transferi"
	e.Text = []byte(fmt.Sprintf("Merhaba, %s size %s dosyasını gönderdi. İndirmek için: %s", from, filename, link))
	err := e.Send("smtp.gmail.com:587", smtp.PlainAuth("", "mertseydim32@gmail.com", "inhr hdqd cize yfii", "smtp.gmail.com"))
	if err != nil {
		log.Println("Email gönderme hatası:", err)
	}
}
