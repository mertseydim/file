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
	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

var (
	db        *sql.DB
	appDomain string
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
)

func main() {
	appDomain = os.Getenv("APP_DOMAIN")
	if appDomain == "" {
		appDomain = "https://mertseydim.com.tr"
	}
	if string(jwtSecret) == "" {
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

	app.Post("/register", register)
	app.Post("/login", login)
	app.Post("/upload", uploadFile)
	app.Get("/history", jwtMiddleware, getHistory)
	app.Get("/download/:link", downloadFile)

	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	log.Fatal(app.Listen(":3000"))
}

func initDB() error {
	user := os.Getenv("DB_USER")
	if user == "" {
		user = "root"
	}
	pass := os.Getenv("DB_PASS")
	if pass == "" {
		return fmt.Errorf("DB_PASS environment variable not set")
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
		return fmt.Errorf("failed to open database: %w", err)
	}
	if err = db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			id INT AUTO_INCREMENT PRIMARY KEY,
			sender_id INT,
			sender_email VARCHAR(255),
			receiver_email VARCHAR(255),
			file_name VARCHAR(255),
			file_size BIGINT,
			file_path VARCHAR(512),
			download_link VARCHAR(36) UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create files table: %w", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	return nil
}

func register(c *fiber.Ctx) error {
	type RegisterRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("Register body parse error: %v", err)
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}

	if !isValidEmail(req.Email) {
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz email formatı"})
	}
	if len(req.Password) < 8 {
		return c.Status(400).JSON(fiber.Map{"error": "Şifre en az 8 karakter olmalı"})
	}

	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&exists)
	if err != nil {
		log.Printf("Register DB query error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Veritabanı hatası"})
	}
	if exists > 0 {
		return c.Status(409).JSON(fiber.Map{"error": "Bu email zaten kayıtlı"})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Password hash error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Şifre hashleme hatası"})
	}

	_, err = db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, hash)
	if err != nil {
		log.Printf("Register DB insert error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Kayıt hatası"})
	}

	return c.JSON(fiber.Map{"message": "Kullanıcı başarıyla kaydedildi"})
}

func login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("Login body parse error: %v", err)
		return c.Status(400).JSON(fiber.Map{"error": "Geçersiz istek"})
	}

	var id int
	var hash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", req.Email).Scan(&id, &hash)
	if err == sql.ErrNoRows {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz email veya şifre"})
	} else if err != nil {
		log.Printf("Login DB query error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Veritabanı hatası"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz email veya şifre"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": id,
		"email":   req.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Token creation error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Token oluşturma hatası"})
	}

	return c.JSON(fiber.Map{"token": tokenString})
}

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
		log.Printf("Invalid token: %v", err)
		return c.Status(401).JSON(fiber.Map{"error": "Geçersiz token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("Invalid JWT claims")
		return c.Status(500).JSON(fiber.Map{"error": "Geçersiz token içeriği"})
	}
	userID, ok := claims["user_id"].(float64)
	if !ok {
		log.Printf("Invalid user_id in claims")
		return c.Status(500).JSON(fiber.Map{"error": "Geçersiz kullanıcı kimliği"})
	}
	c.Locals("user_id", userID)
	c.Locals("user_email", claims["email"])

	return c.Next()
}

func uploadFile(c *fiber.Ctx) error {
	var sender string
	var senderID *int
	var fileType string
	auth := c.Get("Authorization")
	if auth != "" && strings.HasPrefix(auth, "Bearer ") {
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			log.Printf("Upload token validation error: %v", err)
			return c.Status(401).JSON(fiber.Map{"error": "Geçersiz token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("Invalid JWT claims in upload")
			return c.Status(500).JSON(fiber.Map{"error": "Geçersiz token içeriği"})
		}
		sender, ok = claims["email"].(string)
		if !ok {
			log.Printf("Invalid email in claims")
			return c.Status(500).JSON(fiber.Map{"error": "Geçersiz email"})
		}
		id, ok := claims["user_id"].(float64)
		if !ok {
			log.Printf("Invalid user_id in claims")
			return c.Status(500).JSON(fiber.Map{"error": "Geçersiz kullanıcı kimliği"})
		}
		idInt := int(id)
		senderID = &idInt
	} else {
		sender = c.FormValue("sender")
		if sender == "" || !isValidEmail(sender) {
			return c.Status(400).SendString("Geçersiz gönderen email")
		}
	}

	receiver := c.FormValue("receiver")
	if receiver == "" || !isValidEmail(receiver) {
		return c.Status(400).SendString("Geçersiz alıcı email")
	}

	file, err := c.FormFile("file")
	if err != nil {
		log.Printf("Upload file error: %v", err)
		return c.Status(400).SendString("Dosya yüklenemedi")
	}
	if file.Size > 1024*1024*1024 {
		return c.Status(400).SendString("Dosya 1GB'dan büyük")
	}

	// Extract file type (extension)
	fileType = filepath.Ext(file.Filename)
	if fileType != "" {
		fileType = strings.ToLower(strings.TrimPrefix(fileType, ".")) // e.g., "pdf" instead of ".pdf"
	} else {
		fileType = "unknown"
	}

	safeFilename := sanitizeFilename(file.Filename)

	link := uuid.New().String()
	dir := "./uploads"
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		log.Printf("Upload directory creation error: %v", err)
		return c.Status(500).SendString("Dizin oluşturma hatası")
	}
	path := filepath.Join(dir, link+"_"+safeFilename)
	if err := c.SaveFile(file, path); err != nil {
		log.Printf("File save error: %v", err)
		return c.Status(500).SendString("Dosya kaydetme hatası")
	}

	_, err = db.Exec("INSERT INTO files (sender_id, sender_email, receiver_email, file_name, file_size, file_path, download_link) VALUES (?, ?, ?, ?, ?, ?, ?)",
		senderID, sender, receiver, file.Filename, file.Size, path, link)
	if err != nil {
		log.Printf("Upload DB insert error: %v", err)
		os.Remove(path)
		return c.Status(500).SendString("Veritabanı hatası")
	}

	downloadLink := fmt.Sprintf("%s/download/%s", appDomain, link)
	if err := sendEmail(receiver, sender, file.Filename, file.Size, fileType, downloadLink); err != nil {
		log.Printf("Email sending error: %v", err)
		return c.Status(500).SendString("Dosya yüklendi ancak email gönderilemedi")
	}

	return c.SendString("Dosya yüklendi ve link gönderildi")
}

func getHistory(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(float64)
	if !ok {
		log.Printf("Invalid user_id in history")
		return c.Status(500).JSON(fiber.Map{"error": "Geçersiz kullanıcı kimliği"})
	}

	rows, err := db.Query("SELECT file_name, file_size, receiver_email, created_at FROM files WHERE sender_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		log.Printf("History DB query error: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Veritabanı hatası"})
	}
	defer rows.Close()

	var history []fiber.Map
	for rows.Next() {
		var fileName, receiverEmail string
		var fileSize int64
		var createdAt time.Time
		if err := rows.Scan(&fileName, &fileSize, &receiverEmail, &createdAt); err != nil {
			log.Printf("History scan error: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Sorgu hatası"})
		}
		history = append(history, fiber.Map{
			"file_name":      fileName,
			"file_size":      fileSize,
			"receiver_email": receiverEmail,
			"created_at":     createdAt.Format("2006-01-02 15:04:05"),
		})
	}

	return c.JSON(history)
}

func downloadFile(c *fiber.Ctx) error {
	link := c.Params("link")
	var path, name string
	err := db.QueryRow("SELECT file_path, file_name FROM files WHERE download_link = ?", link).Scan(&path, &name)
	if err != nil {
		log.Printf("Download DB query error: %v", err)
		return c.Status(404).SendString("Dosya bulunamadı")
	}
	file, err := os.Open(path)
	if err != nil {
		log.Printf("File open error: %v", err)
		return c.Status(500).SendString("Dosya açma hatası")
	}
	defer file.Close()
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	c.Set("Content-Type", "application/octet-stream")
	_, err = io.Copy(c.Response().BodyWriter(), file)
	if err != nil {
		log.Printf("File copy error: %v", err)
		return c.Status(500).SendString("Dosya indirme hatası")
	}

	// Cleanup: Delete file only
	defer os.Remove(path)

	return nil
}

func sendEmail(to, from, filename string, fileSize int64, fileType, link string) error {
	apiKey := os.Getenv("SENDGRID_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("SENDGRID_API_KEY ortam değişkeni ayarlanmadı")
	}

	// Format file size for readability (e.g., KB, MB)
	fileSizeStr := formatFileSize(fileSize)

	fromEmail := mail.NewEmail("SeydimDosya", from)
	toEmail := mail.NewEmail("Alıcı", to)
	subject := "Yeni Dosya Transferi"
	plainTextContent := fmt.Sprintf("Merhaba, %s size %s dosyasını gönderdi.\nDosya Türü: %s\nBoyut: %s\nİndirmek için: %s", from, filename, fileType, fileSizeStr, link)
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
			<p><strong>Dosya Türü:</strong> %s</p>
			<p><strong>Boyut:</strong> %s</p>
			<p>İndirmek için aşağıdaki bağlantıya tıklayın:</p>
			<a href="%s">Dosyayı İndir</a>
		</div>
	</body>
	</html>`, from, filename, fileType, fileSizeStr, link)

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

func formatFileSize(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	if size >= GB {
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	} else if size >= MB {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	} else if size >= KB {
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	}
	return fmt.Sprintf("%d bytes", size)
}

func isValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`).MatchString(email)
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	invalidChars := regexp.MustCompile(`[/:*?"<>|\\]`)
	return invalidChars.ReplaceAllString(name, "_")
}