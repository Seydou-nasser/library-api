package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/seydou-nasser/library-api/config"
	"github.com/seydou-nasser/library-api/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var AccessTokenSecretKey string
var RefreshTokenSecretKey string

var AccessTokenExpireTime time.Duration
var RefreshTokenExpireTime time.Duration

func main() {

	env := config.NewEnv()

	AccessTokenSecretKey = env.AccessTokenSecretKey
	RefreshTokenSecretKey = env.RefreshTokenSecretKey
	AccessTokenExpireTime = time.Duration(env.AccessTokenExpiresIn) * time.Minute
	RefreshTokenExpireTime = time.Duration(env.RefreshTokenExpiresIn) * time.Hour
	host := env.Host
	port := env.Port
	dbName := env.Dbname
	userN := env.User
	password := env.Password
	sslmode := env.Sslmode

	// Connect to the PostgreSQL database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", host, userN, password, dbName, port, sslmode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to database: " + err.Error())
	}

	db.AutoMigrate(&models.Book{})
	db.AutoMigrate(&models.User{})

	r := gin.Default()

	// Route publique pour la connexion et l'inscription
	r.POST("/api/login", loginHandler(db))

	r.POST("/api/register", registerHandler(db))

	r.GET("/api/refresh-token", refreshTokenHandler)

	// Route securisée pour les livres
	sr := r.Group("/api")

	sr.Use(authMiddleware)

	sr.GET("/books", getBooksHandler(db))

	sr.GET("/books/:id", getBookByIdHandler(db))

	sr.GET("/user/books", getUserBooksHandler(db))

	sr.POST("/books", addBooksHandler(db))

	sr.PUT("/books/:id", checkBookOwnershipMiddleware(db), updateBooksByIdHandler(db))

	sr.DELETE("/books/:id", checkBookOwnershipMiddleware(db), deleteBookByIdHandler(db)).Use()

	r.Run("localhost:8080")
}

// books handlers

// Handler pour récupérer tous les livres
func getBooksHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var bks []models.Book
		if err := db.Find(&bks).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la récupération des livres"})
			return
		}
		c.JSON(http.StatusOK, bks)
	}
}

// Handler pour récupérer un livre par son ID
func getBookByIdHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var bk models.Book
		if err := db.First(&bk, "id = ?", id).Error; err != nil {
			c.IndentedJSON(http.StatusNotFound, gin.H{"message": "Le livre recherché n'existe pas !"})
			return
		}
		c.IndentedJSON(http.StatusOK, bk)
	}
}

// Handler pour ajouter un livre
func addBooksHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var newAddBook models.AddBookDTO

		if err := c.ShouldBindJSON(&newAddBook); err != nil {
			if strings.Contains(err.Error(), "required") {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Champs obligatoires manquants"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Format JSON invalide"})
			}
			return
		}

		newBook := models.Book{
			ID:        generateID(),
			Title:     newAddBook.Title,
			Author:    newAddBook.Author,
			Year:      newAddBook.Year,
			Pages:     newAddBook.Pages,
			Price:     newAddBook.Price,
			Publisher: newAddBook.Publisher,
			UserID:    c.MustGet("userId").(string),
		}

		result := db.Create(&newBook)
		if result.Error != nil {
			fmt.Println(result.Error)
			if result.Error == gorm.ErrDuplicatedKey {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de l'ajout du livre"})
				return
			}
		}

		c.IndentedJSON(http.StatusCreated, newBook)
	}
}

// Handler pour mettre à jour un livre par son ID
func updateBooksByIdHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		var updatedBook models.UpdateBookDTO

		if err := c.ShouldBindJSON(&updatedBook); err != nil {
			if strings.Contains(err.Error(), "required") {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Champs obligatoires manquants"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Format JSON invalide"})
			}
			return
		}

		result := db.Model(&models.Book{}).Where("id = ?", id).Updates(models.Book{
			Title:     updatedBook.Title,
			Author:    updatedBook.Author,
			Year:      updatedBook.Year,
			Pages:     updatedBook.Pages,
			Price:     updatedBook.Price,
			Publisher: updatedBook.Publisher,
		})

		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"message": "Livre non trouvé"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la mise à jour du livre", "error": result.Error.Error()})
			}
			return
		}

		c.Status(http.StatusOK)
	}
}

// Handler pour supprimer un livre par son ID
func deleteBookByIdHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		result := db.Delete(&models.Book{}, "id = ?", id)
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "Livre non trouvé"})
			return
		} else if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la suppression du livre", "error": result.Error.Error()})
			return
		}

		c.Status(http.StatusOK)
	}
}

// Handler pour recuperer les livres d'un utilisateur
func getUserBooksHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("userId").(string)
		var books []models.Book
		if err := db.Where("user_id = ?", userID).Find(&books).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la récupération des livres de l'utilisateur"})
			return
		}
		c.JSON(http.StatusOK, books)
	}
}

// refresh token handler
func refreshTokenHandler(c *gin.Context) {
	token := strings.Split(c.Request.Header.Get("Authorization"), " ")
	if len(token) < 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token es obligatoire"})
		return
	}

	// Vérifie le token de rafraichissement
	err := verifyToken(token[1], RefreshTokenSecretKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token non valide"})
		return
	}

	userID, _ := getUserIDFromToken(token[1])

	newToken, err := generateToken(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la génération du token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

// Middleware de vérification de l'appartenance du livre à l'utilisateur
func checkBookOwnershipMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		BookId := c.Param("id")
		var book models.Book
		// Vérifier si le livre existe dans la base de données
		if err := db.Where("id = ?", BookId).First(&book).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"message": "Livre non trouvé"})
				c.Abort()
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la récupération du livre", "error": err.Error()})
			c.Abort()
			return
		}
		// Vérifier si le livre appartient à l'utilisateur
		if book.UserID != c.MustGet("userId").(string) {
			c.JSON(http.StatusForbidden, gin.H{"message": "Vous n'êtes pas autorisé à modifier ce livre"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// fonction de génération d'ID unique
func generateID() string {
	return uuid.New().String()
}

// fonction de génération et de vérification du token JWT

func generateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"exp":    time.Now().Add(AccessTokenExpireTime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(AccessTokenSecretKey))
}

func verifyToken(tokenString string, secret string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("token non valide")
	}

	return nil
}

// fonction de génération du token de rafraichissement
func generateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"exp":    time.Now().Add(RefreshTokenExpireTime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(RefreshTokenSecretKey))
}

// fonction de recuperation de l'ID de l'utilisateur à partir du token
func getUserIDFromToken(tokenString string) (string, error) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(AccessTokenSecretKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := claims["userId"].(string)
		return userID, nil
	}

	return "", fmt.Errorf("token non valide")
}

// middleware d'authentification
func authMiddleware(c *gin.Context) {
	token := strings.Split(c.Request.Header.Get("Authorization"), " ")
	if len(token) < 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token es obligatoire"})
		c.Abort()
		return
	}

	err := verifyToken(token[1], AccessTokenSecretKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token non valide"})
		c.Abort()
		return
	}

	userID, _ := getUserIDFromToken(token[1])
	c.Set("userId", userID)
	c.Next()
}

// handlers de login et register
func loginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var loginUser models.User
		if err := c.ShouldBindJSON(&loginUser); err != nil {
			if strings.Contains(err.Error(), "required") {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Champs obligatoires manquants"})
				return
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Format JSON invalide"})
				return
			}
		}

		// Vérifier si l'utilisateur existe dans la base de données
		result := db.Where("username = ? AND password = ?", loginUser.Username, loginUser.Password).First(&loginUser)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Nom d'utilisateur ou mot de passe invalide"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la connexion"})
			return
		}

		token, refreshToken, shouldReturn := generateTokenAndRefrechToken(loginUser.ID, c)
		if shouldReturn {
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token, "refreshToken": refreshToken})
	}
}

func registerHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var newUser models.User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			if strings.Contains(err.Error(), "required") {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Champs obligatoires manquants"})
				return
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "Format JSON invalide"})
				return
			}
		}
		var tp models.User
		// Vérifier si l'utilisateur existe déjà dans la base de données
		result := db.Where("username = ?", newUser.Username).First(&tp)
		if result.Error == nil {
			c.JSON(http.StatusConflict, gin.H{"message": "Nom d'utilisateur déjà pris"})
			return
		}
		if result.Error != gorm.ErrRecordNotFound {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de l'inscription"})
			return
		}

		// Créer un nouvel utilisateur dans la base de données
		newUser.ID = generateID()
		if err := db.Create(&newUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de l'inscription"})
			return
		}

		// Générer un token JWT et un token de rafraichissement pour l'utilisateur
		token, refreshToken, shouldReturn := generateTokenAndRefrechToken(newUser.ID, c)
		if shouldReturn {
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token, "refreshToken": refreshToken})

	}
}

func generateTokenAndRefrechToken(Id string, c *gin.Context) (string, string, bool) {
	token, err := generateToken(Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la génération du token"})
		return "", "", true
	}

	refreshToken, err := generateRefreshToken(Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la génération du token de rafraichissement"})
		return "", "", true
	}
	return token, refreshToken, false
}
