package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/seydou-nasser/library-api/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var secretKey string

const tokenExpireTime = 1 * time.Minute

func main() {

	if err := godotenv.Load(".env"); err != nil {
		panic("Impossible de charger le fichier .env : " + err.Error())
	}

	secretKey = os.Getenv("secretKey")
	host := os.Getenv("host")
	port := os.Getenv("port")
	dbName := os.Getenv("dbName")
	userN := os.Getenv("user")
	password := os.Getenv("password")

	if host == "" || port == "" || dbName == "" || userN == "" || password == "" || secretKey == "" {
		panic("Veillez à remplir tous les champs dans le fichier .env !")
	}

	// Connect to the PostgreSQL database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", host, userN, password, dbName, port)
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

	// Route securisée pour les livres
	sr := r.Group("/api")

	sr.Use(authMiddleware)

	sr.GET("/books", getBooksHandler(db))

	sr.GET("/books/:id", getBookByIdHandler(db))

	sr.POST("/books", addBooksHandler(db))

	sr.PUT("/books/:id", updateBooksByIdHandler(db))

	sr.DELETE("/books/:id", deleteBookByIdHandler(db))

	r.Run("localhost:8080")
}

// books handlers

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
				return
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la mise à jour du livre", "error": result.Error.Error()})
				return
			}
		}

		c.Status(http.StatusOK)
	}
}

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

func generateID() string {
	return uuid.New().String()
}

// fonction de génération et de vérification du token JWT

func generateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"exp":    time.Now().Add(tokenExpireTime).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("token non valide")
	}

	return nil
}

// middleware d'authentification

func authMiddleware(c *gin.Context) {
	token := strings.Split(c.Request.Header.Get("Authorization"), " ")
	if len(token) < 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token es obligatoire"})
		c.Abort()
		return
	}

	err := verifyToken(token[1])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Token non valide"})
		c.Abort()
		return
	}

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

		token, err := generateToken(loginUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la génération du token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
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
		// Générer un token JWT pour l'utilisateur
		token, err := generateToken(newUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Erreur lors de la génération du token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})

	}
}
