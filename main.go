package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"diplom-auth/database"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

var jwtSecret = []byte("your-secret-key") // В продакшене использовать безопасный ключ

func main() {
	// Инициализация базы данных
	if err := database.InitDB(); err != nil {
		log.Fatal("Ошибка инициализации базы данных:", err)
	}

	r := gin.Default()

	// Статические файлы
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*")

	// Публичные маршруты
	r.GET("/", func(c *gin.Context) {
		// Проверяем токен при загрузке главной страницы
		tokenString := c.GetHeader("Authorization")
		if tokenString != "" {
			if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
				tokenString = tokenString[7:]
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
				}
				return jwtSecret, nil
			})

			if err == nil && token.Valid {
				c.Redirect(http.StatusFound, "/dashboard")
				return
			}
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Школьный SSO",
		})
	})

	// API маршруты
	api := r.Group("/api")
	{
		api.POST("/register", handleRegister)
		api.POST("/login", handleLogin)
		api.GET("/verify", handleVerify)
	}

	// Защищенные маршруты
	dashboard := r.Group("/dashboard")
	dashboard.Use(authMiddleware())
	{
		dashboard.GET("", func(c *gin.Context) {
			c.HTML(http.StatusOK, "dashboard.html", gin.H{
				"title": "Личный кабинет",
				"user": gin.H{
					"username": c.GetString("username"),
					"role":     c.GetString("role"),
				},
			})
		})
		dashboard.GET("/profile", handleGetProfile)
		dashboard.PUT("/profile", handleUpdateProfile)
		dashboard.DELETE("/profile", handleDeleteProfile)
	}

	log.Fatal(r.Run(":8080"))
}

func handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	// Проверка существования пользователя
	var exists bool
	err := database.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)",
		req.Username, req.Email).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пользователь уже существует"})
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	// Создание пользователя
	result, err := database.DB.Exec(
		"INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
		req.Username, req.Email, string(hashedPassword), "student",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания пользователя"})
		return
	}

	userID, _ := result.LastInsertId()
	token, err := generateToken(userID, req.Username, "student")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания токена"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Регистрация успешна",
		"token":   token,
	})
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	var user User
	err := database.DB.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверное имя пользователя или пароль"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверное имя пользователя или пароль"})
		return
	}

	// Генерация токена
	token, err := generateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания токена"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Вход выполнен успешно",
		"token":   token,
		"user": gin.H{
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func handleVerify(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен не предоставлен"})
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	// Удаляем префикс "Bearer " если он есть
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":  claims["user_id"],
		"username": claims["username"],
		"role":     claims["role"],
	})
}

func generateToken(userID int64, username, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Токен действителен 24 часа
	})

	return token.SignedString(jwtSecret)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Проверяем токен в заголовке
		tokenString := c.GetHeader("Authorization")

		// Если токена нет в заголовке, проверяем в GET-параметре
		if tokenString == "" {
			tokenString = c.Query("token")
			if tokenString != "" {
				// Если токен найден в GET-параметре, устанавливаем его в заголовок
				c.Request.Header.Set("Authorization", "Bearer "+tokenString)
			}
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Требуется авторизация"})
			c.Abort()
			return
		}

		// Удаляем префикс "Bearer " если он есть
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен"})
			c.Abort()
			return
		}

		// Проверяем срок действия токена
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Срок действия токена истек"})
				c.Abort()
				return
			}
		}

		c.Set("user_id", int64(claims["user_id"].(float64)))
		c.Set("username", claims["username"].(string))
		c.Set("role", claims["role"].(string))
		c.Next()
	}
}

func handleGetProfile(c *gin.Context) {
	userID := c.GetInt64("user_id")
	var user User
	err := database.DB.QueryRow(
		"SELECT id, username, email, role, created_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.CreatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func handleUpdateProfile(c *gin.Context) {
	userID := c.GetInt64("user_id")
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	var query string
	var args []interface{}

	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
			return
		}
		query = "UPDATE users SET email = ?, password = ? WHERE id = ?"
		args = []interface{}{req.Email, string(hashedPassword), userID}
	} else {
		query = "UPDATE users SET email = ? WHERE id = ?"
		args = []interface{}{req.Email, userID}
	}

	_, err := database.DB.Exec(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления данных"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Профиль успешно обновлен"})
}

func handleDeleteProfile(c *gin.Context) {
	userID := c.GetInt64("user_id")
	_, err := database.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления профиля"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Профиль успешно удален"})
}
