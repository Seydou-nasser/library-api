Créer une petite API REST avec Gin pour gérer une bibliothèque de livres. L’API permettra d’ajouter, lister, mettre à jour et supprimer des livres. Les données seront stockées en mémoire (pas besoin de base de données pour commencer).

### Point determinaison

- GET /api/books - Récupérer tous les livres
- GET /api/books/:id - Récupérer un livre spécifique par son ID
- POST /api/books - Ajouter un nouveau livre
- PUT /api/books/:id - Mettre à jour un livre existant
- DELETE /api/books/:id - Supprimer un livre

{
"title": "Le Comte de Monte-Cristo",
"author": "Alexandre Dumas",
"year": 1844,
"pages": 1276,
"price": 19.99,
"publisher": "Gallimard"
}

{
"title": "1984",
"author": "George Orwell",
"year": 1949,
"pages": 328,
"price": 15.99,
"publisher": "Secker & Warburg"
}

{
"title": "Le Petit Prince",
"author": "Antoine de Saint-Exupéry",
"year": 1943,
"pages": 96,
"price": 10.99,
"publisher": "Reynal & Hitchcock"
}
