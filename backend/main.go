package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/html"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Database Models
type URL struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	URL               string    `json:"url" gorm:"unique;not null"`
	Title             string    `json:"title"`
	HTMLVersion       string    `json:"html_version"`
	Status            string    `json:"status" gorm:"default:'queued'"` // queued, running, done, error
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	H1Count           int       `json:"h1_count"`
	H2Count           int       `json:"h2_count"`
	H3Count           int       `json:"h3_count"`
	H4Count           int       `json:"h4_count"`
	H5Count           int       `json:"h5_count"`
	H6Count           int       `json:"h6_count"`
	InternalLinks     int       `json:"internal_links"`
	ExternalLinks     int       `json:"external_links"`
	InaccessibleLinks int       `json:"inaccessible_links"`
	HasLoginForm      bool      `json:"has_login_form"`
	ErrorMessage      string    `json:"error_message"`
}

type BrokenLink struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	URLID      uint      `json:"url_id"`
	URL        *URL      `json:"url" gorm:"foreignKey:URLID"`
	LinkURL    string    `json:"link_url"`
	StatusCode int       `json:"status_code"`
	CreatedAt  time.Time `json:"created_at"`
}

// Request/Response types
type CrawlRequest struct {
	URL string `json:"url" binding:"required"`
}

type BulkActionRequest struct {
	URLIDs []uint `json:"url_ids" binding:"required"`
	Action string `json:"action" binding:"required"`
}

type PaginationRequest struct {
	Page     int    `json:"page" form:"page"`
	PageSize int    `json:"page_size" form:"page_size"`
	Sort     string `json:"sort" form:"sort"`
	Order    string `json:"order" form:"order"`
	Search   string `json:"search" form:"search"`
	Filter   string `json:"filter" form:"filter"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}

type URLDetailResponse struct {
	URL         URL          `json:"url"`
	BrokenLinks []BrokenLink `json:"broken_links"`
}

var db *gorm.DB
var jwtSecret = []byte("your-secret-key-change-in-production")

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Database connection
func connectDB() {
	// Getting database config data from env
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "3306"
	}
	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "root"
	}
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		dbPassword = "password"
	}
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "webcrawler"
	}
	log.Printf("Connecting to database at %s:%s", dbHost, dbPort)
	log.Printf("User: %s/***", dbUser)

	// Retrying connection
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		// First try to create database if it doesn't exist
		createDBDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/", dbUser, dbPassword, dbHost, dbPort)
		if sqlDB, err := sql.Open("mysql", createDBDSN); err == nil {
			sqlDB.Exec("CREATE DATABASE IF NOT EXISTS " + dbName)
			sqlDB.Close()
		}
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			dbUser, dbPassword, dbHost, dbPort, dbName)
		var err error
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err == nil {
			if err := db.AutoMigrate(&URL{}, &BrokenLink{}); err != nil {
				log.Printf("Database migration failed: %v", err)
			} else {
				log.Println("Database connected successfully")
			}
			return
		}
		log.Printf("Database connection failed: %v", err)
		if i < maxRetries-1 {
			waitTime := time.Duration(i+1) * 2 * time.Second
			log.Printf("Retrying in %v...", waitTime)
			time.Sleep(waitTime)
		}
	}

	log.Printf("Failed to connect to database after %d attempts", maxRetries)
	log.Println("The application will continue without database - some of the features will not work properly.")
}

// JWT Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove Bearer prefix
		if strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*Claims); ok {
			c.Set("user_id", claims.UserID)
			c.Set("username", claims.Username)
		}

		c.Next()
	}
}

// Generating JWT Token
func generateToken(userID uint, username string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Auth endpoints
func login(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if loginReq.Username == "admin" && loginReq.Password == "password" {
		token, err := generateToken(1, loginReq.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"token":    token,
			"username": loginReq.Username,
		})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

// Web Crawler Functionality
// This function crawls a given URL, analyzes the HTML content, and finds broken links.
// It updates the URL record in the database and returns the results.
func crawlURL(urlStr string) (*URL, []BrokenLink, error) {
	var urlRecord URL
	if err := db.Where("url = ?", urlStr).First(&urlRecord).Error; err != nil {
		return nil, nil, fmt.Errorf("URL record not found: %w", err)
	}
	urlRecord.Status = "running"
	db.Save(&urlRecord)
	log.Printf("Starting to crawl URL: %s (ID: %d)", urlStr, urlRecord.ID)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(urlStr)
	if err != nil {
		urlRecord.Status = "error"
		urlRecord.ErrorMessage = err.Error()
		db.Save(&urlRecord)
		log.Printf("Failed to fetch URL %s: %v", urlStr, err)
		return &urlRecord, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		urlRecord.Status = "error"
		urlRecord.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		db.Save(&urlRecord)
		log.Printf("HTTP error for URL %s: %d", urlStr, resp.StatusCode)
		return &urlRecord, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Parsing the HTML document
	doc, err := html.Parse(resp.Body)
	if err != nil {
		urlRecord.Status = "error"
		urlRecord.ErrorMessage = "Failed to parse HTML"
		db.Save(&urlRecord)
		log.Printf("Failed to parse HTML for URL %s: %v", urlStr, err)
		return &urlRecord, nil, err
	}
	log.Printf("Successfully parsed HTML for URL: %s", urlStr)
	urlRecord.H1Count = 0
	urlRecord.H2Count = 0
	urlRecord.H3Count = 0
	urlRecord.H4Count = 0
	urlRecord.H5Count = 0
	urlRecord.H6Count = 0
	urlRecord.InternalLinks = 0
	urlRecord.ExternalLinks = 0
	urlRecord.HasLoginForm = false
	analyzeDocument(doc, &urlRecord, urlStr)
	// Update URL record with analysis results
	log.Printf("Analysis completed for URL %s: H1=%d, H2=%d, Internal=%d, External=%d",
		urlStr, urlRecord.H1Count, urlRecord.H2Count, urlRecord.InternalLinks, urlRecord.ExternalLinks)

	db.Where("url_id = ?", urlRecord.ID).Delete(&BrokenLink{})
	// Find broken links
	brokenLinks := findBrokenLinks(doc, urlStr, urlRecord.ID)
	urlRecord.InaccessibleLinks = len(brokenLinks)

	log.Printf("Found %d broken links for URL: %s", len(brokenLinks), urlStr)
	// Save the URL record with updated analysis
	urlRecord.Status = "done"
	urlRecord.ErrorMessage = ""
	db.Save(&urlRecord)
	log.Printf("Crawling completed successfully for URL: %s", urlStr)
	return &urlRecord, brokenLinks, nil
}

func analyzeDocument(n *html.Node, urlRecord *URL, baseURL string) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "html":
			// Check the HTML version
			for _, attr := range n.Attr {
				if attr.Key == "version" {
					urlRecord.HTMLVersion = attr.Val
				}
			}
			// Default to HTML5
			if urlRecord.HTMLVersion == "" {
				urlRecord.HTMLVersion = "HTML5"
			}
		case "title":
			if n.FirstChild != nil {
				urlRecord.Title = n.FirstChild.Data
			}
		case "h1":
			urlRecord.H1Count++
		case "h2":
			urlRecord.H2Count++
		case "h3":
			urlRecord.H3Count++
		case "h4":
			urlRecord.H4Count++
		case "h5":
			urlRecord.H5Count++
		case "h6":
			urlRecord.H6Count++
		case "a":
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					if isInternalLink(attr.Val, baseURL) {
						urlRecord.InternalLinks++
					} else {
						urlRecord.ExternalLinks++
					}
				}
			}
		case "form":
			// Check if the form has a password field or common login patterns
			if hasLoginForm(n) {
				urlRecord.HasLoginForm = true
			}
		}
	}
	// Check for DOCTYPE to determine HTML version
	if n.Type == html.DoctypeNode {
		doctype := strings.ToLower(n.Data)
		if strings.Contains(doctype, "html") {
			if strings.Contains(doctype, "4.01") {
				urlRecord.HTMLVersion = "HTML 4.01"
			} else if strings.Contains(doctype, "xhtml") {
				urlRecord.HTMLVersion = "XHTML"
			} else {
				urlRecord.HTMLVersion = "HTML5"
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		analyzeDocument(c, urlRecord, baseURL)
	}
}

func isInternalLink(href, baseURL string) bool {
	if href == "" || strings.HasPrefix(href, "#") {
		return true
	}
	if strings.HasPrefix(href, "/") {
		return true
	}
	linkURL, err := url.Parse(href)
	if err != nil {
		return false
	}
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	return linkURL.Host == baseURLParsed.Host || linkURL.Host == ""
}

func hasLoginForm(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, attr := range n.Attr {
			if attr.Key == "type" && attr.Val == "password" {
				return true
			}
		}
	}
	for _, attr := range n.Attr {
		if attr.Key == "id" || attr.Key == "class" || attr.Key == "name" {
			val := strings.ToLower(attr.Val)
			if strings.Contains(val, "login") || strings.Contains(val, "signin") || strings.Contains(val, "auth") {
				return true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if hasLoginForm(c) {
			return true
		}
	}

	return false
}

func findBrokenLinks(n *html.Node, baseURL string, urlID uint) []BrokenLink {
	var brokenLinks []BrokenLink
	var links []string

	// Collect all links from the HTML document
	collectLinks(n, &links)
	count := 0
	for _, link := range links {
		if count >= 10 {
			break
		}
		if link == "" || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "tel:") {
			continue
		}
		fullURL := resolveURL(link, baseURL)
		if fullURL == "" {
			continue
		}
		// Check if the URL is already in the database
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		resp, err := client.Head(fullURL)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 400 {
			brokenLink := BrokenLink{
				URLID:      urlID,
				LinkURL:    fullURL,
				StatusCode: resp.StatusCode,
			}
			brokenLinks = append(brokenLinks, brokenLink)
			db.Create(&brokenLink)
			count++
		}
	}

	return brokenLinks
}

func collectLinks(n *html.Node, links *[]string) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" {
				*links = append(*links, attr.Val)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectLinks(c, links)
	}
}

func resolveURL(href, baseURL string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	linkURL, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return baseURLParsed.ResolveReference(linkURL).String()
}

// Api handlers
func addURL(c *gin.Context) {
	var req CrawlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}
	// Create a new URL record
	urlRecord := URL{
		URL:    req.URL,
		Status: "queued",
		Title:  "Untitled",
	}
	if err := db.Create(&urlRecord).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save URL"})
		return
	}
	c.JSON(http.StatusCreated, urlRecord)
}

func getURLs(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}
	// Parse pagination and filtering parameters
	var req PaginationRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Set default values
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}
	if req.Sort == "" {
		req.Sort = "created_at"
	}
	if req.Order == "" {
		req.Order = "desc"
	}

	query := db.Model(&URL{})
	// Filter by search term
	if req.Search != "" {
		query = query.Where("url LIKE ? OR title LIKE ?", "%"+req.Search+"%", "%"+req.Search+"%")
	}
	// Filter by status
	if req.Filter != "" && req.Filter != "all" {
		query = query.Where("status = ?", req.Filter)
	}
	// Count total records for pagination
	var total int64
	query.Count(&total)
	// Apply sorting
	orderBy := req.Sort + " " + req.Order
	query = query.Order(orderBy)
	// Apply pagination
	offset := (req.Page - 1) * req.PageSize
	query = query.Limit(req.PageSize).Offset(offset)
	// Fetch the URLs
	var urls []URL
	if err := query.Find(&urls).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch URLs"})
		return
	}

	totalPages := int((total + int64(req.PageSize) - 1) / int64(req.PageSize))
	response := PaginatedResponse{
		Data:       urls,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

func getURLDetails(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL ID"})
		return
	}
	var urlRecord URL
	if err := db.First(&urlRecord, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "URL not found"})
		return
	}
	var brokenLinks []BrokenLink
	db.Where("url_id = ?", id).Find(&brokenLinks)

	response := URLDetailResponse{
		URL:         urlRecord,
		BrokenLinks: brokenLinks,
	}
	c.JSON(http.StatusOK, response)
}

func startCrawling(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL ID"})
		return
	}
	var urlRecord URL
	if err := db.First(&urlRecord, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "URL not found"})
		return
	}

	go func() {
		_, _, err := crawlURL(urlRecord.URL)
		if err != nil {
			log.Printf("Crawling failed for URL %s: %v", urlRecord.URL, err)
		}
	}()
	c.JSON(http.StatusOK, gin.H{
		"message": "Crawling started",
		"url_id":  id,
	})
}

func stopCrawling(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid URL ID"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Crawling stop requested",
		"url_id":  id,
	})
}

func bulkAction(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Database not available"})
		return
	}
	var req BulkActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	switch req.Action {
	case "delete":
		if err := db.Where("id IN ?", req.URLIDs).Delete(&URL{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete URLs"})
			return
		}
		db.Where("url_id IN ?", req.URLIDs).Delete(&BrokenLink{})
	case "rerun":
		if err := db.Model(&URL{}).Where("id IN ?", req.URLIDs).Update("status", "queued").Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update URLs"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Bulk %s completed", req.Action),
	})
}

func main() {
	// Set Gin to release mode
	router := gin.Default()
	// Enable CORS for specific origins
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173", "http://localhost:8081"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// Set up routes
	router.POST("/login", login)

	router.GET("/health", func(c *gin.Context) {
		dbStatus := "not_connected"
		if db != nil {
			// Test the connection
			sqlDB, err := db.DB()
			if err == nil && sqlDB.Ping() == nil {
				dbStatus = "connected"
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"status":   "ok",
			"service":  "web-crawler-backend",
			"auth":     "implemented",
			"database": dbStatus,
		})
	})
	// Start database connection in background
	go func() {
		log.Println("Starting database connection in background...")
		connectDB()
	}()
	// API routes
	api := router.Group("/api")
	api.Use(authMiddleware())
	{
		api.POST("/urls", addURL)
		api.GET("/urls", getURLs)
		api.GET("/urls/:id", getURLDetails)
		api.POST("/urls/:id/start", startCrawling)
		api.POST("/urls/:id/stop", stopCrawling)
		api.POST("/urls/bulk", bulkAction)
	}
	// Start the server
	log.Println("Starting server...")
	// Set the port from environment variable or default to 8080
	// This allows the server to run in different environments easily
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}
