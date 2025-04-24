package models

type Book struct {
	ID        string  `json:"id"`
	Title     string  `json:"title" gorm:"unique"`
	Author    string  `json:"author"`
	Year      int     `json:"year"`
	Pages     int     `json:"pages"`
	Price     float64 `json:"price"`
	Publisher string  `json:"publisher"`
	UserID    string  `json:"user_id"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username" binding:"required" gorm:"unique"`
	Password string `json:"password" binding:"required"`
	Books    []Book `json:"books" gorm:"foreignKey:UserID"`
}

type AddBookDTO struct {
	Title     string  `json:"title" binding:"required"`
	Author    string  `json:"author" binding:"required"`
	Year      int     `json:"year" binding:"required"`
	Pages     int     `json:"pages" binding:"required"`
	Price     float64 `json:"price" binding:"required"`
	Publisher string  `json:"publisher" binding:"required"`
}

type UpdateBookDTO struct {
	Title     string  `json:"title" binding:"required"`
	Author    string  `json:"author" binding:"required"`
	Year      int     `json:"year" binding:"required"`
	Pages     int     `json:"pages" binding:"required"`
	Price     float64 `json:"price" binding:"required"`
	Publisher string  `json:"publisher" binding:"required"`
}
