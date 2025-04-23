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
)

type book struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Author    string  `json:"author"`
	Year      int     `json:"year"`
	Pages     int     `json:"pages"`
	Price     float64 `json:"price"`
	Publisher string  `json:"publisher"`
}

type addBookDTO struct {
	Title     string  `json:"title" binding:"required"`
	Author    string  `json:"author" binding:"required"`
	Year      int     `json:"year" binding:"required"`
	Pages     int     `json:"pages" binding:"required"`
	Price     float64 `json:"price" binding:"required"`
	Publisher string  `json:"publisher" binding:"required"`
}

type updateBookDTO struct {
	Title     string  `json:"title" binding:"required"`
	Author    string  `json:"author" binding:"required"`
	Year      int     `json:"year" binding:"required"`
	Pages     int     `json:"pages" binding:"required"`
	Price     float64 `json:"price" binding:"required"`
	Publisher string  `json:"publisher" binding:"required"`
}

var secretKey string

const tokenExpireTime = 24 * time.Hour

var books = []book{}

func main() {

	if err := godotenv.Load(".env"); err != nil {
		panic("Impossible de charger le fichier .env : " + err.Error())
	}
	secretKey = os.Getenv("secretKey")
	if secretKey == "" {
		panic("La variable n'a pas été définie !")
	}

	r := gin.Default()

	r.GET("/api/get-token", func(c *gin.Context) {
		userID := uuid.New().String()
		token, err := generateToken(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	// r.GET("/api/verify-token", func(c *gin.Context) {
	// 	tokenString := c.Query("token")
	// 	if tokenString == "" {
	// 		c.JSON(http.StatusBadRequest, gin.H{"message": "Token is required"})
	// 		return
	// 	}

	// 	err := verifyToken(tokenString)
	// 	if err != nil {
	// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token", "details": err.Error()})
	// 		return
	// 	}
	// 	c.JSON(http.StatusOK, gin.H{"message": "Token is valid"})
	// })

	sr := r.Group("/api")

	sr.Use(authMiddleware)

	sr.GET("/books", getBooksHandler)

	sr.GET("/books/:id", getBookByIdHandler)

	sr.POST("/books", addBooksHandler)

	sr.PUT("/books/:id", updateBooksByIdHandler)

	sr.DELETE("/books/:id", deleteBookById)

	r.Run("localhost:8080")
}

func getBooksHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, books)
}

func getBookByIdHandler(c *gin.Context) {
	id := c.Param("id")
	for _, bk := range books {
		if bk.ID == id {
			c.IndentedJSON(http.StatusOK, bk)
			return
		}
	}

	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "Livre non trouvé !"})

}

func addBooksHandler(c *gin.Context) {
	var newAddBook addBookDTO

	if err := c.ShouldBindJSON(&newAddBook); err != nil {
		if strings.Contains(err.Error(), "required") {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Champs obligatoires manquants", "details": err.Error()})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Format JSON invalide", "details": err.Error()})
		}
		return
	}

	newBook := book{
		ID:        uuid.New().String(),
		Title:     newAddBook.Title,
		Author:    newAddBook.Author,
		Year:      newAddBook.Year,
		Pages:     newAddBook.Pages,
		Price:     newAddBook.Price,
		Publisher: newAddBook.Publisher,
	}

	books = append(books, newBook)

	c.IndentedJSON(http.StatusCreated, newBook)

}

func updateBooksByIdHandler(c *gin.Context) {
	id := c.Param("id")

	var updatedBook updateBookDTO

	if err := c.ShouldBindJSON(&updatedBook); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"message": "Une erreur est survenue !",
			"error":   err.Error(),
		})
		return
	}

	for i, bk := range books {
		if bk.ID == id {
			books[i] = book{
				ID:        bk.ID,
				Title:     updatedBook.Title,
				Author:    updatedBook.Author,
				Year:      updatedBook.Year,
				Pages:     updatedBook.Pages,
				Price:     updatedBook.Price,
				Publisher: updatedBook.Publisher,
			}
			c.IndentedJSON(http.StatusAccepted, books[i])
			return
		}
	}

	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "le livre n'existe pas!"})
}

func deleteBookById(c *gin.Context) {
	id := c.Param("id")

	for i, bk := range books {
		if bk.ID == id {
			books = append(books[:i], books[i+1:]...)
			c.Status(http.StatusOK)
			return
		}
	}

	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "le livre n'existe pas!"})
}

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
