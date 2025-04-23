package route

import "github.com/gin-gonic/gin"

func newBookRoutes(rg *gin.RouterGroup) {
	rg.POST("/books", addBook)
	rg.GET("/books", getBooks)
	rg.GET("/books/:id", getBookByID)
	rg.PUT("/books/:id", updateBook)
	rg.DELETE("/books/:id", deleteBook)
}
