# Этап сборки
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Устанавливаем необходимые зависимости для сборки
RUN apk add --no-cache gcc musl-dev

# Копируем файлы зависимостей
COPY go.mod ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN CGO_ENABLED=1 GOOS=linux go build -o main .

# Финальный этап
FROM alpine:latest

WORKDIR /app

# Устанавливаем необходимые зависимости для SQLite
RUN apk add --no-cache sqlite

# Копируем бинарный файл из этапа сборки
COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Создаем директорию для базы данных
RUN mkdir -p /app/data

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./main"] 