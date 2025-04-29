package models

type Book struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Genre       string  `json:"genre"`
	Author      string  `json:"author"`
	Year        int     `json:"year"`
	Pages       int     `json:"pages"`
	Price       float64 `json:"price"`
	Publisher   string  `json:"publisher"`
	UserID      string  `json:"userId"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
	Email    string `json:"email" gorm:"unique"`
	Books    []Book `json:"books" gorm:"foreignKey:UserID"`
}

type AddBookDTO struct {
	Title       string  `json:"title" binding:"required"`
	Description string  `json:"description"`
	Genre       string  `json:"genre"`
	Author      string  `json:"author" binding:"required"`
	Year        int     `json:"year" binding:"required"`
	Pages       int     `json:"pages" binding:"required"`
	Price       float64 `json:"price" binding:"required"`
	Publisher   string  `json:"publisher" binding:"required"`
}

func (b *AddBookDTO) ConvertToBook() Book {
	return Book{
		Title:       b.Title,
		Description: b.Description,
		Genre:       b.Genre,
		Author:      b.Author,
		Year:        b.Year,
		Pages:       b.Pages,
		Price:       b.Price,
		Publisher:   b.Publisher,
	}
}

type UpdateBookDTO struct {
	Title       string  `json:"title" binding:"required"`
	Description string  `json:"description"`
	Genre       string  `json:"genre"`
	Author      string  `json:"author" binding:"required"`
	Year        int     `json:"year" binding:"required"`
	Pages       int     `json:"pages" binding:"required"`
	Price       float64 `json:"price" binding:"required"`
	Publisher   string  `json:"publisher" binding:"required"`
}

func (b *UpdateBookDTO) ConvertToBook() Book {
	return Book{
		Title:       b.Title,
		Description: b.Description,
		Genre:       b.Genre,
		Author:      b.Author,
		Year:        b.Year,
		Pages:       b.Pages,
		Price:       b.Price,
		Publisher:   b.Publisher,
	}
}
