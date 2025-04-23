Créer une petite API REST avec Gin pour gérer une bibliothèque de livres. L’API permettra d’ajouter, lister, mettre à jour et supprimer des livres. Les données seront stockées en mémoire (pas besoin de base de données pour commencer).

### Point de terminaison

- GET /api/books - Récupérer tous les livres
- GET /api/books/:id - Récupérer un livre spécifique par son ID
- POST /api/books - Ajouter un nouveau livre
- PUT /api/books/:id - Mettre à jour un livre existant
- DELETE /api/books/:id - Supprimer un livre
