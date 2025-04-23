package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

var books = []book{}

func main() {

	router := gin.Default()

	router.GET("/api/books", getBooksHandler)

	router.GET("/api/books/:id", getBookByIdHandler)

	router.POST("/api/books", addBooksHandler)

	router.PUT("/api/books/:id", updateBooksByIdHandler)

	router.DELETE("/api/books/:id", deleteBookById)

	router.Run("localhost:8080")
}

func getBooksHandler(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, books)
}

func getBookByIdHandler(c *gin.Context) {
	id := c.Param("id")
	for _, bk := range books {
		if bk.ID == id {
			c.IndentedJSON(http.StatusOK, bk) // et non StatusFound
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
