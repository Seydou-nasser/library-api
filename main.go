package main

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	middleware "github.com/seydou-nasser/library-api/Middleware"
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

	r.GET("/api/verify-token", func(c *gin.Context) {
		tokenString := c.Query("token")
		if tokenString == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Token is required"})
			return
		}

		err := verifyToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token", "details": err.Error(), "token": tokenString})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Token is valid"})
	})

	sr := r.Group("/api")

	sr.Use(middleware.AuthMiddleware)

	sr.GET("/books", getBooksHandler)

	sr.GET("/books/:id", getBookByIdHandler)

	sr.POST("/books", addBooksHandler)

	sr.PUT("/books/:id", updateBooksByIdHandler)

	sr.DELETE("/books/:id", deleteBookById)

	r.Run("localhost:8080")
}
