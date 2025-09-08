package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	appDomain string
	jwtSecret = []byte(os.Getenv("JWT_SECRET")) // New: Load from env
)

func main() {
	appDomain = os.Getenv("APP_DOMAIN")
	if appDomain == "" {
		appDomain = "http://localhost:3000"
	}
	if string(jwtSecret) == "" { // New: Check JWT secret
		log.Fatal("JWT_SECRET environment variable not set")
	}

	app := fiber.New(fiber.Config{
		BodyLimit:    1024 * 1024 * 1024, // 1GB
		ReadTimeout:  60 * time.Minute,
		WriteTimeout: 60 * time.Minute,
	})
	app.Use(logger.New())

	app.Static("/", "./public")

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("./public/index.html")
	})

	// New: Registration and login routes
	app.Post("/register", register)
	app.Post("/login", login)

	app.Post("/upload", jwtMiddleware, uploadFile)

	app.Get("/download/:link", downloadFile)

	initDB()

	log.Fatal(app.Listen(":3000"))
}

func initDB() {
	user := os.Getenv("DB_USER")
	if user == "" {
		user = "root"
	}
	pass := os.Getenv("DB_PASS")
	if pass == "" {
		log.Fatal("DB_PASS environment variable not set")
	}
	config := mysql.Config{
		User:   user,
		Passwd: pass,
		Net:    "tcp",
		Addr:   "127.0.0.1:3306",
		DBName: "file_transfer_db",
	}
	var err error
	db, err = sql.Open("mysql", config.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	// Existing files table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			id INT AUTO_INCREMENT PRIMARY KEY,
			sender_email VARCHAR(255),
			receiver_email VARCHAR(255),
			file_name VARCHAR(255),
			file_path VARCHAR(512),
			download_link VARCHAR(36) UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal("Failed to create files table:", err)
	}

	// New: Users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}
}

// New: Registration handler
func register(c *fiber.Ctx) error {
	type RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}

	// Validate email and password
	if !isValidEmail(req.Email) {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz email formatı"})
	}
	if len(req.Password) < 8 {
		return c.Status(400).JSON(fiber.Map{"error": "Şifre en az 8 karakter olmalı"})
	}

	// Check if email exists
	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&exists)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Veritabanı hatası"})
	}
	if exists > 0 {
		return c.Status(409).JSON(fiber.Map{"error": "Bu email zaten kayıtlı"})
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Şifre hashleme hatası"})
	}

	// Insert user
	_, err = db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, hash)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Kayıt hatası"})
	}

	return c.JSON(fiber.Map{"message": "Kullanıcı başarıyla kaydedildi"})
}

// New: Login handler
func login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}

	// Fetch user
	var id int
	var hash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", req.Email).Scan(&id, &hash)
	if err == sql.ErrNoRows {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz email veya şifre"})
	} else if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Veritabanı hatası"})
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz email veya şifre"})
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": id,
		"email":   req.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24-hour expiration
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token oluşturma hatası"})
	}

	return c.JSON(fiber.Map{"token": tokenString})
}

// New: JWT middleware (optional, apply to protected routes)
func jwtMiddleware(c *fiber.Ctx) error {
	auth := c.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return c.Status(401).JSON(fiber.Map{"error": "Yetkisiz erişim"})
	}
	tokenString := strings.TrimPrefix(auth, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz token"})
	}

	// Optional: Set user context
	claims := token.Claims.(jwt.MapClaims)
	c.Locals("user_email", claims["email"])

	return c.Next()
}

// Helper: Basic email validation
func isValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`).MatchString(email)
}

func uploadFile(c *fiber.Ctx) error {
	sender := c.Locals("user_email").(string)
	receiver := c.FormValue("receiver")
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).SendString("Dosya yüklenemedi")
	}
	if file.Size > 1024*1024*1024 {
		return c.Status(400).SendString("Dosya 1GB'dan büyük")
	}

	// Sanitize filename
	safeFilename := sanitizeFilename(file.Filename)

	link := uuid.New().String()
	dir := "./uploads"
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return c.Status(500).SendString("Dizin oluşturma hatası")
	}
	path := filepath.Join(dir, link+"_"+safeFilename)
	if err := c.SaveFile(file, path); err != nil {
		return c.Status(500).SendString("Dosya kaydetme hatası")
	}

	_, err = db.Exec("INSERT INTO files (sender_email, receiver_email, file_name, file_path, download_link) VALUES (?, ?, ?, ?, ?)",
		sender, receiver, file.Filename, path, link)
	if err != nil {
		os.Remove(path) // Cleanup on failure
		return c.Status(500).SendString("Veritabanı hatası")
	}

	downloadLink := fmt.Sprintf("%s/download/%s", appDomain, link)
	if err := sendEmail(receiver, sender, file.Filename, downloadLink); err != nil {
		log.Println("Email gönderme hatası:", err)
		return c.Status(500).SendString("Dosya yüklendi ancak email gönderilemedi")
	}

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

	// Cleanup: Delete file and DB entry after download
	defer func() {
		os.Remove(path)
		db.Exec("DELETE FROM files WHERE download_link = ?", link)
	}()

	return nil
}

func sendEmail(to, from, filename, link string) error {
	apiKey := os.Getenv("SENDGRID_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("SENDGRID_API_KEY ortam değişkeni ayarlanmadı")
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
		return fmt.Errorf("email gönderme hatası: %w", err)
	}
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("email gönderme başarısız: %d - %s", response.StatusCode, response.Body)
	}
	return nil
}

// Helper to sanitize filename
func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	invalidChars := regexp.MustCompile(`[/:*?"<>|\\]`)
	return invalidChars.ReplaceAllString(name, "_")
}
