// Basic routing with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })
    http.ListenAndServe(":8080", r)
}



// Handling route parameters with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/user/{id}", func(w http.ResponseWriter, r *http.Request) {
        id := chi.URLParam(r, "id")
        w.Write([]byte("User ID: " + id))
    })
    http.ListenAndServe(":8080", r)
}




// Serving static files with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/*", http.FileServer(http.Dir("./static")).ServeHTTP)
    http.ListenAndServe(":8080", r)
}





// Applying middleware with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })
    http.ListenAndServe(":8080", r)
}




// Using sub-routers with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Route("/admin", func(r chi.Router) {
        r.Get("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Admin Dashboard"))
        })
        r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("List of Users"))
        })
    })
    http.ListenAndServe(":8080", r)
}





// Handling different HTTP methods with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("GET Request"))
    })
    r.Post("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("POST Request"))
    })
    r.Put("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("PUT Request"))
    })
    r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("DELETE Request"))
    })
    http.ListenAndServe(":8080", r)
}





// Grouping routes with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Route("/users", func(r chi.Router) {
        r.Get("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("List of Users"))
        })
        r.Post("/", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Create User"))
        })
    })
    http.ListenAndServe(":8080", r)
}





// Validating URL parameters with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
    "gopkg.in/go-playground/validator.v9"
)

type User struct {
    ID   string `validate:"uuid"`
    Name string `validate:"required"`
}

func main() {
    r := chi.NewRouter()
    r.Use(middleware.ValidateURLParams(
        validator.New(),
    ))

    r.Get("/user/{id}", func(w http.ResponseWriter, r *http.Request) {
        id := chi.URLParam(r, "id")
        w.Write([]byte("User ID: " + id))
    })

    r.Post("/user", func(w http.ResponseWriter, r *http.Request) {
        var user User
        if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
            w.WriteHeader(http.StatusBadRequest)
            w.Write([]byte("Bad request"))
            return
        }
        validate := validator.New()
        if err := validate.Struct(user); err != nil {
            w.WriteHeader(http.StatusBadRequest)
            w.Write([]byte("Validation error"))
            return
        }
        w.Write([]byte("User created"))
    })

    http.ListenAndServe(":8080", r)
}





// Implementing custom middleware with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func MyCustomMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Custom middleware logic here
        next.ServeHTTP(w, r)
    })
}

func main() {
    r := chi.NewRouter()
    r.Use(MyCustomMiddleware)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })
    http.ListenAndServe(":8080", r)
}





// Implementing graceful shutdown with Chi.
package main

import (
    "context"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil {
            if err == http.ErrServerClosed {
                return
            }
            panic(err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        panic(err)
    }
}




// Implementing HTTP/2 server push with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        pusher, ok := w.(http.Pusher)
        if ok {
            if err := pusher.Push("/styles.css", nil); err != nil {
                http.Error(w, "Failed to push: "+err.Error(), http.StatusInternalServerError)
                return
            }
        }
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing rate limiting with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
    "golang.org/x/time/rate"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.NewRateLimit(
        rate.NewLimiter(rate.Limit(5), 10),
    ))

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing basic authentication with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.BasicAuth("user", "password"))

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Authenticated"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing JWT authentication with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/jwtauth"
)

func main() {
    r := chi.NewRouter()

    jwt := jwtauth.New("HS256", []byte("secret"), nil)

    r.Group(func(r chi.Router) {
        r.Use(jwtauth.Verifier(jwt))
        r.Use(jwtauth.Authenticator)

        r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Authenticated"))
        })
    })

    http.ListenAndServe(":8080", r)
}




// Handling WebSocket connections with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
}

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    r.Get("/ws", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            http.Error(w, "Could not open WebSocket connection", http.StatusBadRequest)
            return
        }
        defer conn.Close()

        for {
            _, _, err := conn.ReadMessage()
            if err != nil {
                return
            }
        }
    })

    http.ListenAndServe(":8080", r)
}





// Handling WebSocket connections with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
}

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    r.Get("/ws", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            http.Error(w, "Could not open WebSocket connection", http.StatusBadRequest)
            return
        }
        defer conn.Close()

        for {
            _, _, err := conn.ReadMessage()
            if err != nil {
                return
            }
        }
    })

    http.ListenAndServe(":8080", r)
}




// Handling request context with Chi.
package main

import (
    "context"
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        ctx = context.WithValue(ctx, "key", "value")
        // Use ctx in subsequent handlers
        w.Write([]byte("Context handled"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing a custom 404 handler with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.NotFound(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusNotFound)
        w.Write([]byte("Custom 404 Not Found"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing context cancellation with Chi.
package main

import (
    "context"
    "net/http"
    "time"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
        defer cancel()

        // Perform operations with ctx
        w.Write([]byte("Context cancelled after 5 seconds"))
    })

    http.ListenAndServe(":8080", r)
}




// Using multiple middlewares with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}




// Handling request headers with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        headerValue := r.Header.Get("Header-Name")
        w.Write([]byte("Header Value: " + headerValue))
    })

    http.ListenAndServe(":8080", r)
}




// Setting response headers with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Custom-Header", "value")
        w.Write([]byte("Response with custom header"))
    })

    http.ListenAndServe(":8080", r)
}




// Handling errors with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        // Simulate an error
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
    })

    http.ListenAndServe(":8080", r)
}




// Serving a Single Page Application (SPA) with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()

    // Serve static files
    fs := http.FileServer(http.Dir("./static"))
    r.Handle("/*", http.StripPrefix("/", fs))

    // SPA routing
    r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "./static/index.html")
    })

    http.ListenAndServe(":8080", r)
}




// Handling cookies with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
        cookie := http.Cookie{
            Name:  "username",
            Value: "john_doe",
        }
        http.SetCookie(w, &cookie)
        w.Write([]byte("Cookie set"))
    })

    r.Get("/get-cookie", func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("username")
        if err != nil {
            w.Write([]byte("No cookie found"))
            return
        }
        w.Write([]byte("Cookie value: " + cookie.Value))
    })

    http.ListenAndServe(":8080", r)
}




// Handling request timeout with Chi.
package main

import (
    "context"
    "net/http"
    "time"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
        defer cancel()

        select {
        case <-time.After(3 * time.Second):
            w.Write([]byte("Operation completed"))
        case <-ctx.Done():
            w.Write([]byte("Request timed out"))
        }
    })

    http.ListenAndServe(":8080", r)
}





// Handling redirects with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/redirect", func(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, "/destination", http.StatusTemporaryRedirect)
    })

    r.Get("/destination", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Redirected to destination"))
    })

    http.ListenAndServe(":8080", r)
}





// Handling form data with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Post("/form", func(w http.ResponseWriter, r *http.Request) {
        err := r.ParseForm()
        if err != nil {
            http.Error(w, "Failed to parse form", http.StatusBadRequest)
            return
        }
        username := r.Form.Get("username")
        password := r.Form.Get("password")
        // Handle form data
        w.Write([]byte("Received form data"))
    })

    http.ListenAndServe(":8080", r)
}





// Implementing request logging with Chi.
package main

import (
    "net/http"
    "os"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}




// Implementing gzip compression with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Compress(5))

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}




// Chaining custom middleware with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
)

func FirstMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // First middleware logic
        next.ServeHTTP(w, r)
    })
}

func SecondMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Second middleware logic
        next.ServeHTTP(w, r)
    })
}

func main() {
    r := chi.NewRouter()
    r.Use(FirstMiddleware)
    r.Use(SecondMiddleware)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, Chi!"))
    })

    http.ListenAndServe(":8080", r)
}





// Implementing custom error handling middleware with Chi.
package main

import (
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
)

func CustomErrorHandler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if r := recover(); r != nil {
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

func main() {
    r := chi.NewRouter()
    r.Use(CustomErrorHandler)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        // Simulate an error
        panic("Something went wrong")
    })

    http.ListenAndServe(":8080", r)
}





// Using context-based middleware with Chi.
package main

import (
    "net/http"
    "time"

    "github.com/go-chi/chi"
)

func TimeoutMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
        defer cancel()

        r = r.WithContext(ctx)
        next.ServeHTTP(w, r)
    })
}

func main() {
    r := chi.NewRouter()
    r.Use(TimeoutMiddleware)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(3 * time.Second) // Simulate a long operation
        w.Write([]byte("Operation completed"))
    })

    http.ListenAndServe(":8080", r)
}





// Streaming responses with Chi.
package main

import (
    "net/http"
    "strconv"
    "time"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/stream", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")

        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                w.Write([]byte("data: " + strconv.FormatInt(time.Now().Unix(), 10) + "\n\n"))
                w.(http.Flusher).Flush()
            case <-r.Context().Done():
                return
            }
        }
    })

    http.ListenAndServe(":8080", r)
}





// Handling file uploads with Chi.
package main

import (
    "fmt"
    "net/http"
    "os"
    "path/filepath"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Post("/upload", func(w http.ResponseWriter, r *http.Request) {
        file, handler, err := r.FormFile("file")
        if err != nil {
            http.Error(w, "Failed to get file", http.StatusBadRequest)
            return
        }
        defer file.Close()

        // Save uploaded file
        filePath := filepath.Join("./uploads", handler.Filename)
        f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
        if err != nil {
            http.Error(w, "Failed to save file", http.StatusInternalServerError)
            return
        }
        defer f.Close()
        _, err = io.Copy(f, file)
        if err != nil {
            http.Error(w, "Failed to save file", http.StatusInternalServerError)
            return
        }

        w.Write([]byte(fmt.Sprintf("File %s uploaded successfully", handler.Filename)))
    })

    http.ListenAndServe(":8080", r)
}




// Parsing and validating requests with Chi.
package main

import (
    "encoding/json"
    "net/http"

    "github.com/go-chi/chi"
    "github.com/go-chi/chi/middleware"
    "gopkg.in/go-playground/validator.v9"
)

type User struct {
    ID   string `json:"id" validate:"required"`
    Name string `json:"name" validate:"required"`
}

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    r.Post("/user", func(w http.ResponseWriter, r *http.Request) {
        var user User
        err := json.NewDecoder(r.Body).Decode(&user)
        if err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        validate := validator.New()
        if err := validate.Struct(user); err != nil {
            http.Error(w, "Validation error", http.StatusBadRequest)
            return
        }

        // Process valid user
        w.Write([]byte("User created"))
    })

    http.ListenAndServe(":8080", r)
}





// Implementing a reverse proxy with Chi.
package main

import (
    "net/http"
    "net/http/httputil"
    "net/url"

    "github.com/go-chi/chi"
)

func main() {
    r := chi.NewRouter()

    r.Get("/proxy", func(w http.ResponseWriter, r *http.Request) {
        targetURL := "http://example.com"
        url, err := url.Parse(targetURL)
        if err != nil {
            http.Error(w, "Failed to parse target URL", http.StatusInternalServerError)
            return
        }

        proxy := httputil.NewSingleHostReverseProxy(url)
        proxy.ServeHTTP(w, r)
    })

    http.ListenAndServe(":8080", r)
}





// Implementing a custom response writer with Chi.
package main

import (
    "net/http"
    "bytes"
    "log"

    "github.com/go-chi/chi"
)

type customResponseWriter struct {
    http.ResponseWriter
    statusCode int
    buffer     *bytes.Buffer
}

func (w *customResponseWriter) WriteHeader(statusCode int) {
    w.statusCode = statusCode
    w.ResponseWriter.WriteHeader(statusCode)
}

func (w *customResponseWriter) Write(data []byte) (int, error) {
    if w.statusCode == 0 {
        w.statusCode = http.StatusOK
    }
    return w.buffer.Write(data)
}

func (w *customResponseWriter) Flush() {
    _, err := w.ResponseWriter.Write(w.buffer.Bytes())
    if err != nil {
        log.Printf("Failed to flush response: %v", err)
    }
}

func main() {
    r := chi.NewRouter()

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        customWriter := &customResponseWriter{
            ResponseWriter: w,
            buffer:         &bytes.Buffer{},
        }

        customWriter.WriteHeader(http.StatusCreated)
        customWriter.Write([]byte("Custom response"))
        customWriter.Flush()
    })

    http.ListenAndServe(":8080", r)
}





// Implementing OAuth authentication with Chi.
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"

    "github.com/go-chi/chi"
)

var googleOAuthConfig = oauth2.Config{
    ClientID:     "CLIENT_ID",
    ClientSecret: "CLIENT_SECRET",
    Endpoint:     google.Endpoint,
    RedirectURL:  "http://localhost:8080/callback",
    Scopes:       []string{"profile", "email"},
}

func main() {
    r := chi.NewRouter()

    r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
        url := googleOAuthConfig.AuthCodeURL("state")
        http.Redirect(w, r, url, http.StatusTemporaryRedirect)
    })

    r.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
        code := r.URL.Query().Get("code")
        token, err := googleOAuthConfig.Exchange(context.Background(), code)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusBadRequest)
            return
        }

        // Use token to get user information
        client := googleOAuthConfig.Client(context.Background(), token)
        profileInfo, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to get user profile: %v", err), http.StatusBadRequest)
            return
        }

        defer profileInfo.Body.Close()

        var profile map[string]interface{}
        if err := json.NewDecoder(profileInfo.Body).Decode(&profile); err != nil {
            http.Error(w, fmt.Sprintf("Failed to decode profile: %v", err), http.StatusInternalServerError)
            return
        }

        fmt.Fprintf(w, "Profile: %+v", profile)
    })

    http.ListenAndServe(":8080", r)
}










package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/storage"
)

func main() {
	// Documentation: Lists all buckets in Google Cloud Storage.
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	buckets, err := client.Buckets(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to list buckets: %v", err)
	}

	fmt.Println("Buckets:")
	for _, bucket := range buckets {
		fmt.Println(bucket.Name)
	}
}





package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/storage"
)

func main() {
	// Documentation: Uploads a file to Google Cloud Storage.
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucket := client.Bucket("your-bucket-name")
	object := bucket.Object("destination-file-name")
	file, err := os.Open("local-file-path")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	wc := object.NewWriter(ctx)
	if _, err = wc.WriteFrom(file); err != nil {
		log.Fatalf("Failed to write file to bucket: %v", err)
	}
	if err := wc.Close(); err != nil {
		log.Fatalf("Failed to close writer: %v", err)
	}

	fmt.Println("File uploaded successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
)

func main() {
	// Documentation: Creates a new Pub/Sub topic.
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	topic := client.Topic("your-topic-name")
	exists, err := topic.Exists(ctx)
	if err != nil {
		log.Fatalf("Failed to check if topic exists: %v", err)
	}
	if exists {
		fmt.Printf("Topic %s already exists.\n", topic.ID())
		return
	}

	_, err = client.CreateTopic(ctx, "your-topic-name")
	if err != nil {
		log.Fatalf("Failed to create topic: %v", err)
	}

	fmt.Println("Topic created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/storage"
)

func main() {
	// Documentation: Deletes a file from Google Cloud Storage.
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucket := client.Bucket("your-bucket-name")
	object := bucket.Object("file-to-delete")

	if err := object.Delete(ctx); err != nil {
		log.Fatalf("Failed to delete object: %v", err)
	}

	fmt.Println("File deleted successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
)

func main() {
	// Documentation: Lists all subscriptions in Google Cloud Pub/Sub.
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	subscriptions, err := client.Subscriptions(ctx)
	if err != nil {
		log.Fatalf("Failed to list subscriptions: %v", err)
	}

	fmt.Println("Subscriptions:")
	for _, sub := range subscriptions {
		fmt.Println(sub.ID())
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
)

func main() {
	// Documentation: Publishes a message to a Google Cloud Pub/Sub topic.
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	topic := client.Topic("your-topic-name")
	result := topic.Publish(ctx, &pubsub.Message{
		Data: []byte("Hello, Cloud Pub/Sub!"),
	})

	// Block until the message is published.
	id, err := result.Get(ctx)
	if err != nil {
		log.Fatalf("Failed to publish message: %v", err)
	}

	fmt.Printf("Message published with ID: %s\n", id)
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Compute Engine instance.
	ctx := context.Background()

	service, err := compute.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Compute Engine service: %v", err)
	}

	project := "your-project-id"
	zone := "your-zone"
	instanceName := "instance-name"
	image := "projects/debian-cloud/global/images/debian-10-buster-v20220315"

	instance := &compute.Instance{
		Name:        instanceName,
		MachineType: fmt.Sprintf("zones/%s/machineTypes/n1-standard-1", zone),
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Mode:       "READ_WRITE",
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: image,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					{
						Type: "ONE_TO_ONE_NAT",
						Name: "External NAT",
					},
				},
				Network: "global/networks/default",
			},
		},
	}

	op, err := service.Instances.Insert(project, zone, instance).Do()
	if err != nil {
		log.Fatalf("Failed to create instance: %v", err)
	}

	fmt.Printf("Instance %s is being created.\n", instanceName)
	fmt.Printf("Operation ID: %s\n", op.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1beta4"
)

func main() {
	// Documentation: Lists all Cloud SQL instances.
	ctx := context.Background()

	service, err := sqladmin.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud SQL service: %v", err)
	}

	instances, err := service.Instances.List("your-project-id").Do()
	if err != nil {
		log.Fatalf("Failed to list instances: %v", err)
	}

	fmt.Println("Cloud SQL Instances:")
	for _, instance := range instances.Items {
		fmt.Printf("%s (%s)\n", instance.Name, instance.Region)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new database in Cloud SQL.
	ctx := context.Background()

	service, err := sqladmin.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud SQL service: %v", err)
	}

	instance := "your-instance-id"
	database := "new-database"

	op, err := service.Databases.Insert("your-project-id", instance, &sqladmin.Database{
		Name: database,
	}).Do()
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}

	fmt.Printf("Database %s created successfully.\n", database)
	fmt.Printf("Operation ID: %s\n", op.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/storage"
)

func main() {
	// Documentation: Lists all objects in a Google Cloud Storage bucket.
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucket := client.Bucket("your-bucket-name")
	objects := bucket.Objects(ctx, nil)

	fmt.Println("Objects in Bucket:")
	for {
		objAttrs, err := objects.Next()
		if err == storage.IterateDone {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate objects: %v", err)
		}
		fmt.Println(objAttrs.Name)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new document in Cloud Firestore.
	ctx := context.Background()

	client, err := firestore.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Firestore client: %v", err)
	}
	defer client.Close()

	docRef := client.Collection("cities").Doc("LA")
	data := map[string]interface{}{
		"name":    "Los Angeles",
		"state":   "CA",
		"country": "USA",
	}

	_, err = docRef.Set(ctx, data)
	if err != nil {
		log.Fatalf("Failed to create document: %v", err)
	}

	fmt.Println("Document created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists all Cloud Functions in a Google Cloud project.
	ctx := context.Background()

	service, err := cloudfunctions.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Functions service: %v", err)
	}

	parent := "projects/your-project-id/locations/-"
	functions, err := service.Projects.Locations.Functions.List(parent).Do()
	if err != nil {
		log.Fatalf("Failed to list functions: %v", err)
	}

	fmt.Println("Cloud Functions:")
	for _, function := range functions.Functions {
		fmt.Printf("%s (%s)\n", function.Name, function.Status)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Google Cloud Storage bucket.
	ctx := context.Background()

	client, err := storage.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucket := "new-bucket-name"
	err = client.Bucket(bucket).Create(ctx, "your-project-id", nil)
	if err != nil {
		log.Fatalf("Failed to create bucket: %v", err)
	}

	fmt.Printf("Bucket %s created successfully.\n", bucket)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/bigquery"
)

func main() {
	// Documentation: Lists all BigQuery datasets in a Google Cloud project.
	ctx := context.Background()

	client, err := bigquery.NewClient(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to create BigQuery client: %v", err)
	}
	defer client.Close()

	datasets := client.Datasets(ctx)
	for {
		dataset, err := datasets.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate datasets: %v", err)
		}
		fmt.Println(dataset.DatasetID)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/spanner/admin/instance/apiv1"
	"google.golang.org/api/option"
	adminpb "google.golang.org/genproto/googleapis/spanner/admin/instance/v1"
)

func main() {
	// Documentation: Creates a new Cloud Spanner instance.
	ctx := context.Background()

	client, err := instance.NewInstanceAdminClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Spanner instance client: %v", err)
	}
	defer client.Close()

	instanceID := "your-instance-id"
	instanceName := "projects/your-project-id/instances/" + instanceID
	config := "regional-us-central1"

	req := &adminpb.CreateInstanceRequest{
		Parent:     "projects/your-project-id",
		InstanceId: instanceID,
		Instance: &adminpb.Instance{
			Name:    instanceName,
			Config:  config,
			NodeCount: 1,
		},
	}

	op, err := client.CreateInstance(ctx, req)
	if err != nil {
		log.Fatalf("Failed to create instance: %v", err)
	}

	fmt.Printf("Instance %s is being created.\n", instanceID)
	fmt.Printf("Operation ID: %s\n", op.Name())
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/bigquery"
)

func main() {
	// Documentation: Inserts a row into a BigQuery table.
	ctx := context.Background()

	client, err := bigquery.NewClient(ctx, "your-project-id")
	if err != nil {
		log.Fatalf("Failed to create BigQuery client: %v", err)
	}
	defer client.Close()

	datasetID := "your-dataset-id"
	tableID := "your-table-id"

	inserter := client.Dataset(datasetID).Table(tableID).Inserter()
	row := map[string]interface{}{
		"column1": "value1",
		"column2": 123,
		"column3": true,
	}

	if err := inserter.Put(ctx, row); err != nil {
		log.Fatalf("Failed to insert row: %v", err)
	}

	fmt.Println("Row inserted successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/datastore"
	"google.golang.org/api/option"
)

type Task struct {
	Description string
	Completed   bool
}

func main() {
	// Documentation: Creates a new entity in Cloud Datastore.
	ctx := context.Background()

	client, err := datastore.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Datastore client: %v", err)
	}
	defer client.Close()

	taskKey := datastore.IncompleteKey("Task", nil)
	task := &Task{
		Description: "Sample task",
		Completed:   false,
	}

	if _, err := client.Put(ctx, taskKey, task); err != nil {
		log.Fatalf("Failed to create task: %v", err)
	}

	fmt.Println("Task created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/iam"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists IAM policies for a Google Cloud resource.
	ctx := context.Background()

	client, err := iam.NewIamClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create IAM client: %v", err)
	}

	resource := "//cloudresourcemanager.googleapis.com/projects/your-project-id"
	policy, err := client.GetPolicy(ctx, &iam.GetPolicyRequest{
		Resource: resource,
	})
	if err != nil {
		log.Fatalf("Failed to get IAM policy: %v", err)
	}

	fmt.Printf("IAM Policy for %s:\n", resource)
	for _, binding := range policy.Bindings {
		fmt.Printf("- Role: %s\n", binding.Role)
		fmt.Println("  Members:")
		for _, member := range binding.Members {
			fmt.Printf("  - %s\n", member)
		}
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud KMS keyring and key.
	ctx := context.Background()

	client, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}
	defer client.Close()

	location := "global"
	keyRing := "your-keyring"
	keyID := "your-key"

	keyRingPath := fmt.Sprintf("projects/your-project-id/locations/%s/keyRings/%s", location, keyRing)
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingPath,
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	}

	key, err := client.CreateCryptoKey(ctx, req)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}

	fmt.Printf("Key %s created in keyring %s.\n", key.Name, keyRingPath)
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/cloudcdn/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists Cloud CDN services in a Google Cloud project.
	ctx := context.Background()

	service, err := cloudcdn.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud CDN service: %v", err)
	}

	project := "projects/your-project-id"
	response, err := service.Projects.Locations.Services.List(project, "global").Do()
	if err != nil {
		log.Fatalf("Failed to list CDN services: %v", err)
	}

	fmt.Println("Cloud CDN Services:")
	for _, cdn := range response.Services {
		fmt.Printf("%s (%s)\n", cdn.Name, cdn.DisplayName)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/scheduler/apiv1"
	"github.com/golang/protobuf/ptypes/duration"
	"google.golang.org/api/option"
	schedulerpb "google.golang.org/genproto/googleapis/cloud/scheduler/v1"
)

func main() {
	// Documentation: Creates a new Cloud Scheduler job.
	ctx := context.Background()

	client, err := scheduler.NewCloudSchedulerClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Scheduler client: %v", err)
	}
	defer client.Close()

	project := "your-project-id"
	location := "your-location" // e.g., "us-central1"
	jobName := "your-job-name"

	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)
	job := &schedulerpb.Job{
		Name: fmt.Sprintf("%s/jobs/%s", parent, jobName),
		Target: &schedulerpb.Job_HttpTarget{
			HttpTarget: &schedulerpb.HttpTarget{
				Uri: "https://example.com",
				HttpMethod: schedulerpb.HttpMethod_GET,
			},
		},
		Schedule: "*/5 * * * *", // Run every 5 minutes
		TimeZone: "UTC",
		RetryConfig: &schedulerpb.RetryConfig{
			RetryCount: 3,
		},
		AttemptDeadline: &duration.Duration{
			Seconds: 600,
		},
	}

	createdJob, err := client.CreateJob(ctx, &schedulerpb.CreateJobRequest{
		Parent: parent,
		Job:    job,
	})
	if err != nil {
		log.Fatalf("Failed to create job: %v", err)
	}

	fmt.Printf("Job %s created successfully.\n", createdJob.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/redis/apiv1"
	"google.golang.org/api/option"
	redispb "google.golang.org/genproto/googleapis/cloud/redis/v1"
)

func main() {
	// Documentation: Lists Cloud Memorystore Redis instances.
	ctx := context.Background()

	client, err := redis.NewCloudRedisClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Memorystore Redis client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id/locations/-"
	response, err := client.ListInstances(ctx, &redispb.ListInstancesRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list Redis instances: %v", err)
	}

	fmt.Println("Cloud Memorystore Redis Instances:")
	for _, instance := range response.Instances {
		fmt.Printf("%s (%s)\n", instance.Name, instance.DisplayName)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a backup for a Cloud SQL instance.
	ctx := context.Background()

	service, err := sqladmin.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud SQL service: %v", err)
	}

	instance := "your-instance-id"
	backupConfig := &sqladmin.BackupConfiguration{
		StartTime: "04:00", // HH:MM format
		Location:  "us-central1",
	}

	op, err := service.BackupRuns.Insert("your-project-id", instance, backupConfig).Do()
	if err != nil {
		log.Fatalf("Failed to create backup: %v", err)
	}

	fmt.Printf("Backup operation ID: %s\n", op.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists triggers for Cloud Functions.
	ctx := context.Background()

	service, err := cloudfunctions.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Functions service: %v", err)
	}

	parent := "projects/your-project-id/locations/-"
	triggers, err := service.Projects.Locations.Triggers.List(parent).Do()
	if err != nil {
		log.Fatalf("Failed to list triggers: %v", err)
	}

	fmt.Println("Cloud Functions Triggers:")
	for _, trigger := range triggers.Triggers {
		fmt.Printf("%s (%s)\n", trigger.Name, trigger.EventType)
	}
}





package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a signed URL for a Cloud Storage object.
	ctx := context.Background()

	client, err := storage.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	bucket := "your-bucket-name"
	object := "your-object-name"
	expiration := time.Now().Add(1 * time.Hour) // URL expires in 1 hour

	url, err := storage.SignedURL(bucket, object, &storage.SignedURLOptions{
		GoogleAccessID: "your-service-account@your-project-id.iam.gserviceaccount.com",
		PrivateKey:     []byte("-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n"),
		Method:         "GET",
		Expires:        expiration,
	})
	if err != nil {
		log.Fatalf("Failed to create signed URL: %v", err)
	}

	fmt.Printf("Signed URL for %s/%s:\n%s\n", bucket, object, url)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/logging"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists Cloud Logging entries.
	ctx := context.Background()

	client, err := logging.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Logging client: %v", err)
	}
	defer client.Close()

	filter := "severity=ERROR"
	iter := client.Entries(ctx, logging.Filter(filter))
	for {
		entry, err := iter.Next()
		if err == logging.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate entries: %v", err)
		}
		fmt.Printf("[%s] %s\n", entry.Timestamp.Format(time.RFC3339), entry.Payload)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/vision/apiv1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud Vision API client.
	ctx := context.Background()

	client, err := vision.NewImageAnnotatorClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Vision API client: %v", err)
	}
	defer client.Close()

	fmt.Println("Vision API client created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists all Cloud Pub/Sub topics in a Google Cloud project.
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Pub/Sub client: %v", err)
	}
	defer client.Close()

	topics, err := client.Topics(ctx)
	if err != nil {
		log.Fatalf("Failed to list topics: %v", err)
	}

	fmt.Println("Cloud Pub/Sub Topics:")
	for _, topic := range topics {
		fmt.Println(topic.ID())
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/language/apiv1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud Natural Language API client.
	ctx := context.Background()

	client, err := language.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Natural Language API client: %v", err)
	}
	defer client.Close()

	fmt.Println("Natural Language API client created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/sqladmin/v1beta4"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists all Cloud SQL instances in a Google Cloud project.
	ctx := context.Background()

	service, err := sqladmin.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud SQL service: %v", err)
	}

	instances, err := service.Instances.List("your-project-id").Do()
	if err != nil {
		log.Fatalf("Failed to list instances: %v", err)
	}

	fmt.Println("Cloud SQL Instances:")
	for _, instance := range instances.Items {
		fmt.Printf("%s (%s)\n", instance.Name, instance.Region)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/iot/apiv1"
	"google.golang.org/api/option"
	iotpb "google.golang.org/genproto/googleapis/cloud/iot/v1"
)

func main() {
	// Documentation: Creates a new Cloud IoT Core device.
	ctx := context.Background()

	client, err := iot.NewDeviceManagerClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create IoT Core client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id/locations/your-region"
	deviceID := "your-device-id"
	device := &iotpb.Device{
		Id:   deviceID,
		Type: iotpb.Device_GATEWAY,
	}

	createdDevice, err := client.CreateDevice(ctx, &iotpb.CreateDeviceRequest{
		Parent: parent,
		Device: device,
	})
	if err != nil {
		log.Fatalf("Failed to create device: %v", err)
	}

	fmt.Printf("Device %s created successfully.\n", createdDevice.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/scheduler/apiv1"
	"google.golang.org/api/option"
	schedulerpb "google.golang.org/genproto/googleapis/cloud/scheduler/v1"
)

func main() {
	// Documentation: Lists Cloud Scheduler jobs in a Google Cloud project.
	ctx := context.Background()

	client, err := scheduler.NewCloudSchedulerClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Scheduler client: %v", err)
	}
	defer client.Close()

	project := "your-project-id"
	location := "your-location" // e.g., "us-central1"

	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)
	response, err := client.ListJobs(ctx, &schedulerpb.ListJobsRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list jobs: %v", err)
	}

	fmt.Println("Cloud Scheduler Jobs:")
	for _, job := range response.Jobs {
		fmt.Printf("%s (%s)\n", job.Name, job.Schedule)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/cloudbuild/apiv1"
	"google.golang.org/api/option"
	cloudbuildpb "google.golang.org/genproto/googleapis/devtools/cloudbuild/v1"
)

func main() {
	// Documentation: Creates a new Cloud Build trigger.
	ctx := context.Background()

	client, err := cloudbuild.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Build client: %v", err)
	}
	defer client.Close()

	project := "your-project-id"
	triggerID := "your-trigger-id"

	trigger := &cloudbuildpb.BuildTrigger{
		TriggerTemplate: &cloudbuildpb.BuildTrigger_GitHub{
			GitHub: &cloudbuildpb.GitHubEventsConfig{
				Owner:      "your-github-owner",
				Repo:       "your-github-repo",
				PullRequest: true,
			},
		},
		Substitutions: map[string]string{
			"_YOUR_VAR": "value",
		},
	}

	createdTrigger, err := client.CreateBuildTrigger(ctx, &cloudbuildpb.CreateBuildTriggerRequest{
		ProjectId: project,
		Trigger:   trigger,
		TriggerId: triggerID,
	})
	if err != nil {
		log.Fatalf("Failed to create build trigger: %v", err)
	}

	fmt.Printf("Build trigger created: %s\n", createdTrigger.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/datastore"
	"google.golang.org/api/option"
)

type Task struct {
	Description string
	Completed   bool
}

func main() {
	// Documentation: Lists entities in Cloud Datastore.
	ctx := context.Background()

	client, err := datastore.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Datastore client: %v", err)
	}
	defer client.Close()

	query := datastore.NewQuery("Task")
	tasks := client.Run(ctx, query)

	fmt.Println("Tasks:")
	for {
		var task Task
		_, err := tasks.Next(&task)
		if err == datastore.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate tasks: %v", err)
		}
		fmt.Printf("- %s (Completed: %v)\n", task.Description, task.Completed)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud Pub/Sub subscription.
	ctx := context.Background()

	client, err := pubsub.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Pub/Sub client: %v", err)
	}
	defer client.Close()

	topicID := "your-topic-id"
	subID := "your-subscription-id"

	topic := client.Topic(topicID)
	sub, err := client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
		Topic: topic,
	})
	if err != nil {
		log.Fatalf("Failed to create subscription: %v", err)
	}

	fmt.Printf("Subscription %s created for topic %s.\n", sub.ID(), topicID)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/redis/apiv1"
	"google.golang.org/api/option"
	redispb "google.golang.org/genproto/googleapis/cloud/redis/v1"
)

func main() {
	// Documentation: Lists Cloud Memorystore Redis instances.
	ctx := context.Background()

	client, err := redis.NewCloudRedisClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Memorystore Redis client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id/locations/-"
	response, err := client.ListInstances(ctx, &redispb.ListInstancesRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list Redis instances: %v", err)
	}

	fmt.Println("Cloud Memorystore Redis Instances:")
	for _, instance := range response.Instances {
		fmt.Printf("%s (%s)\n", instance.Name, instance.DisplayName)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new HTTP-triggered Cloud Function.
	ctx := context.Background()

	service, err := cloudfunctions.NewService(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Functions service: %v", err)
	}

	parent := "projects/your-project-id/locations/-"
	functionID := "your-function-id"

	function := &cloudfunctions.CloudFunction{
		Name:        fmt.Sprintf("projects/your-project-id/locations/-/functions/%s", functionID),
		Description: "HTTP function triggered by HTTP request",
		EntryPoint:  "yourEntryPoint",
		Runtime:     "go113",
		Timeout:     "60s",
		AvailableMemoryMb: 256,
		SourceArchiveUrl: "gs://your-bucket/function-source.zip",
		HttpsTrigger: &cloudfunctions.HttpsTrigger{
			Url: "https://your-cloud-function-url",
		},
	}

	createdFunction, err := service.Projects.Locations.Functions.Create(parent, function).Do()
	if err != nil {
		log.Fatalf("Failed to create function: %v", err)
	}

	fmt.Printf("Cloud Function %s created.\n", createdFunction.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/cloudtasks/apiv2"
	"google.golang.org/api/option"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2"
)

func main() {
	// Documentation: Lists Cloud Tasks queues in a Google Cloud project.
	ctx := context.Background()

	client, err := cloudtasks.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Cloud Tasks client: %v", err)
	}
	defer client.Close()

	project := "your-project-id"
	parent := fmt.Sprintf("projects/%s/locations/-", project)

	response, err := client.ListQueues(ctx, &taskspb.ListQueuesRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list queues: %v", err)
	}

	fmt.Println("Cloud Tasks Queues:")
	for _, queue := range response.Queues {
		fmt.Printf("%s (%s)\n", queue.Name, queue.State)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/iam/admin/apiv1"
	"google.golang.org/api/option"
	iampb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

func main() {
	// Documentation: Creates a new IAM policy binding for a Google Cloud resource.
	ctx := context.Background()

	client, err := admin.NewIamClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create IAM client: %v", err)
	}
	defer client.Close()

	resource := "//cloudresourcemanager.googleapis.com/projects/your-project-id"
	member := "user:your-email@example.com"
	role := "roles/editor"

	policy, err := client.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
		Resource: resource,
		Policy: &iampb.Policy{
			Bindings: []*iampb.Binding{
				{
					Role:    role,
					Members: []string{member},
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to set IAM policy: %v", err)
	}

	fmt.Println("IAM policy binding created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists Cloud Spanner instances in a Google Cloud project.
	ctx := context.Background()

	client, err := spanner.NewInstanceAdminClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Spanner client: %v", err)
	}
	defer client.Close()

	projectID := "your-project-id"
	parent := fmt.Sprintf("projects/%s", projectID)

	iter := client.Instances(ctx, &spannerpb.ListInstancesRequest{
		Parent: parent,
	})
	for {
		instance, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate instances: %v", err)
		}
		fmt.Printf("Instance ID: %s, Display Name: %s\n", instance.Instance, instance.DisplayName)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/bigtable"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new table in Cloud Bigtable.
	ctx := context.Background()

	adminClient, err := bigtable.NewAdminClient(ctx, "your-project-id", "your-instance-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Bigtable admin client: %v", err)
	}
	defer adminClient.Close()

	tableName := "your-table-name"
	err = adminClient.CreateTable(ctx, tableName)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	fmt.Printf("Table %s created successfully in Bigtable.\n", tableName)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/dataflow"
	"google.golang.org/api/option"
	dataflowpb "google.golang.org/genproto/googleapis/dataflow/v1"
)

func main() {
	// Documentation: Lists Cloud Dataflow jobs in a Google Cloud project.
	ctx := context.Background()

	client, err := dataflow.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Dataflow client: %v", err)
	}
	defer client.Close()

	response, err := client.ListJobs(ctx, &dataflowpb.ListJobsRequest{
		ProjectId: "your-project-id",
	})
	if err != nil {
		log.Fatalf("Failed to list jobs: %v", err)
	}

	fmt.Println("Cloud Dataflow Jobs:")
	for _, job := range response.Jobs {
		fmt.Printf("%s (%s)\n", job.Name, job.CurrentState)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/monitoring/dashboard/apiv1"
	"google.golang.org/api/option"
	dashboardpb "google.golang.org/genproto/googleapis/monitoring/dashboard/v1"
)

func main() {
	// Documentation: Creates a new Cloud Monitoring dashboard.
	ctx := context.Background()

	client, err := dashboard.NewDashboardsClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Monitoring client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id"
	dashboard := &dashboardpb.Dashboard{
		Name: "projects/your-project-id/dashboards/your-dashboard-id",
		GridLayout: &dashboardpb.GridLayout{
			Columns: 2,
			Rows:    2,
		},
		Title: "Example Dashboard",
	}

	createdDashboard, err := client.CreateDashboard(ctx, &dashboardpb.CreateDashboardRequest{
		Parent:    parent,
		Dashboard: dashboard,
	})
	if err != nil {
		log.Fatalf("Failed to create dashboard: %v", err)
	}

	fmt.Printf("Dashboard %s created successfully.\n", createdDashboard.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/composer/apiv1"
	"google.golang.org/api/option"
	composerpb "google.golang.org/genproto/googleapis/cloud/composer/v1"
)

func main() {
	// Documentation: Lists Cloud Composer environments in a Google Cloud project.
	ctx := context.Background()

	client, err := composer.NewEnvironmentsClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Composer client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id/locations/-"
	response, err := client.ListEnvironments(ctx, &composerpb.ListEnvironmentsRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list environments: %v", err)
	}

	fmt.Println("Cloud Composer Environments:")
	for _, environment := range response.Environments {
		fmt.Printf("%s (%s)\n", environment.Name, environment.State)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/speech/apiv1"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud Speech-to-Text API client.
	ctx := context.Background()

	client, err := speech.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Speech-to-Text API client: %v", err)
	}
	defer client.Close()

	fmt.Println("Speech-to-Text API client created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists Cloud Firestore databases in a Google Cloud project.
	ctx := context.Background()

	client, err := firestore.NewClient(ctx, "your-project-id", option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Firestore client: %v", err)
	}
	defer client.Close()

	iter := client.Databases(ctx)
	for {
		db, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate databases: %v", err)
		}
		fmt.Printf("Database ID: %s, Project ID: %s\n", db.ID, db.ProjectID)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/translate"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Creates a new Cloud Translation API client.
	ctx := context.Background()

	client, err := translate.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Translation API client: %v", err)
	}
	defer client.Close()

	fmt.Println("Translation API client created successfully.")
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func main() {
	// Documentation: Lists all Cloud Storage buckets in a Google Cloud project.
	ctx := context.Background()

	client, err := storage.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Storage client: %v", err)
	}
	defer client.Close()

	iter := client.Buckets(ctx, "your-project-id")
	for {
		bucketAttrs, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to iterate buckets: %v", err)
		}
		fmt.Println(bucketAttrs.Name)
	}
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/dataproc/apiv1"
	"google.golang.org/api/option"
	dataprocpb "google.golang.org/genproto/googleapis/cloud/dataproc/v1"
)

func main() {
	// Documentation: Creates a new Cloud Dataproc cluster.
	ctx := context.Background()

	client, err := dataproc.NewClusterControllerClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create Dataproc client: %v", err)
	}
	defer client.Close()

	projectID := "your-project-id"
	region := "your-region"
	clusterName := "your-cluster-name"

	cluster := &dataprocpb.Cluster{
		ProjectId: projectID,
		ClusterName: clusterName,
		Config: &dataprocpb.ClusterConfig{
			MasterConfig: &dataprocpb.InstanceGroupConfig{
				NumInstances: 1,
				MachineTypeUri: "n1-standard-4",
			},
			WorkerConfig: &dataprocpb.InstanceGroupConfig{
				NumInstances: 2,
				MachineTypeUri: "n1-standard-4",
			},
		},
	}

	op, err := client.CreateCluster(ctx, &dataprocpb.CreateClusterRequest{
		ProjectId: projectID,
		Region: region,
		Cluster: cluster,
	})
	if err != nil {
		log.Fatalf("Failed to create cluster: %v", err)
	}

	fmt.Printf("Cluster operation ID: %s\n", op.Name)
}





package main

import (
	"context"
	"fmt"
	"log"

	"cloud.google.com/go/aiplatform/operations"
	"google.golang.org/api/option"
	aiplatformpb "google.golang.org/genproto/googleapis/cloud/aiplatform/v1"
)

func main() {
	// Documentation: Lists AI Platform models in a Google Cloud project.
	ctx := context.Background()

	client, err := operations.NewClient(ctx, option.WithCredentialsFile("path-to-service-account-key.json"))
	if err != nil {
		log.Fatalf("Failed to create AI Platform client: %v", err)
	}
	defer client.Close()

	parent := "projects/your-project-id/locations/-"
	response, err := client.ListModels(ctx, &aiplatformpb.ListModelsRequest{
		Parent: parent,
	})
	if err != nil {
		log.Fatalf("Failed to list models: %v", err)
	}

	fmt.Println("AI Platform Models:")
	for _, model := range response.Models {
		fmt.Printf("%s (%s)\n", model.Name, model.DeploymentUri)
	}
}











/*
Example 1: Basic Channel Communication

Description:
This example demonstrates basic communication between two goroutines using CMP library channels.

Steps:
1. Create a new CMP channel.
2. Start a goroutine to send a message through the channel.
3. Receive and print the message in the main goroutine.

Expected Output:
Message received: Hello, CMP!
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		ch.Send("Hello, CMP!")
	}()

	msg := ch.Receive().(string)
	fmt.Println("Message received:", msg)
}





/*
Example 2: Synchronous Message Passing

Description:
This example demonstrates synchronous message passing using CMP library's request-response pattern.

Steps:
1. Create a new CMP channel.
2. Start a goroutine to handle requests.
3. Send a request and receive a response synchronously.

Expected Output:
Request: What is 2 + 2?
Response: 4
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		for {
			req := ch.Receive().(string)
			if req == "quit" {
				break
			}
			if req == "What is 2 + 2?" {
				ch.Send("4")
			}
		}
	}()

	ch.Send("What is 2 + 2?")
	resp := ch.Receive().(string)
	fmt.Println("Response:", resp)

	ch.Send("quit")
}





/*
Example 3: Select Statement with CMP Channels

Description:
This example demonstrates the use of Go's select statement with CMP channels for non-blocking message handling.

Steps:
1. Create two CMP channels.
2. Use select to handle messages from both channels concurrently.

Expected Output:
Messages received:
- Message 1: Hello from Channel 1
- Message 2: Hi from Channel 2
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch1 := cmp.NewChannel()
	ch2 := cmp.NewChannel()

	go func() {
		time.Sleep(1 * time.Second)
		ch1.Send("Hello from Channel 1")
	}()

	go func() {
		time.Sleep(2 * time.Second)
		ch2.Send("Hi from Channel 2")
	}()

	for i := 0; i < 2; i++ {
		select {
		case msg := <-ch1.C:
			fmt.Println("Message 1:", msg.(string))
		case msg := <-ch2.C:
			fmt.Println("Message 2:", msg.(string))
		}
	}
}





/*
Example 4: Buffered Channels with CMP

Description:
This example demonstrates the use of buffered channels with CMP library for handling multiple messages concurrently.

Steps:
1. Create a buffered CMP channel.
2. Send multiple messages to the channel concurrently.
3. Receive and print the messages.

Expected Output:
Messages received:
- Message: Hello, CMP! (received from buffered channel)
- Message: How are you? (received from buffered channel)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewBufferedChannel(2)

	go func() {
		ch.Send("Hello, CMP!")
		ch.Send("How are you?")
	}()

	for i := 0; i < 2; i++ {
		msg := ch.Receive().(string)
		fmt.Println("Message:", msg)
	}
}





/*
Example 5: Timeout Handling with CMP Channels

Description:
This example demonstrates timeout handling using CMP channels in Go.

Steps:
1. Create a CMP channel.
2. Implement a timeout mechanism using select to handle message reception within a specified time.
3. Print message or timeout message based on received message or timeout.

Expected Output:
Message received: Hello, CMP! (if received within timeout)
Or
Timeout: No message received within 1 second. (if timed out)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		time.Sleep(500 * time.Millisecond)
		ch.Send("Hello, CMP!")
	}()

	select {
	case msg := <-ch.C:
		fmt.Println("Message received:", msg.(string))
	case <-time.After(1 * time.Second):
		fmt.Println("Timeout: No message received within 1 second.")
	}
}





/*
Example 6: Broadcast Communication with CMP

Description:
This example demonstrates broadcasting messages to multiple subscribers using CMP channels.

Steps:
1. Create a CMP channel.
2. Start multiple goroutines as subscribers to receive broadcasted messages.
3. Broadcast a message to all subscribers.

Expected Output:
Messages received by subscribers:
- Subscriber 1 received: Hello, CMP!
- Subscriber 2 received: Hello, CMP!
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		fmt.Println("Subscriber 1 received:", ch.Receive().(string))
	}()

	go func() {
		defer wg.Done()
		fmt.Println("Subscriber 2 received:", ch.Receive().(string))
	}()

	ch.Send("Hello, CMP!")

	wg.Wait()
}





/*
Example 7: Select Statement with Timeout for CMP

Description:
This example demonstrates using select with a timeout for CMP channels in Go.

Steps:
1. Create a CMP channel.
2. Implement a select statement with timeout to handle message reception within a specified time.
3. Print received message or timeout message based on the outcome.

Expected Output:
Message received: Hello, CMP! (if received within timeout)
Or
Timeout: No message received within 1 second. (if timed out)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		time.Sleep(500 * time.Millisecond)
		ch.Send("Hello, CMP!")
	}()

	select {
	case msg := <-ch.C:
		fmt.Println("Message received:", msg.(string))
	case <-time.After(1 * time.Second):
		fmt.Println("Timeout: No message received within 1 second.")
	}
}





/*
Example 8: Close and Reopen CMP Channel

Description:
This example demonstrates closing and reopening a CMP channel in Go.

Steps:
1. Create a CMP channel.
2. Close the channel after sending a message.
3. Attempt to send another message after reopening the channel.

Expected Output:
Messages received:
- Message: Hello, CMP! (first message received)
- Message: Hi again! (second message received after reopening)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	ch.Send("Hello, CMP!")
	ch.Close()

	// Reopen channel
	ch = cmp.NewChannel()
	ch.Send("Hi again!")

	fmt.Println("Messages received:")
	fmt.Println("- Message:", ch.Receive().(string))
	fmt.Println("- Message:", ch.Receive().(string))
}





/*
Example 9: CMP Channel with Structured Messages

Description:
This example demonstrates using CMP channels with structured messages (custom types) in Go.

Steps:
1. Define a struct for messages.
2. Create a CMP channel for the struct type.
3. Send and receive structured messages through the channel.

Expected Output:
Message received: {John Doe 30}
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

type Person struct {
	Name string
	Age  int
}

func main() {
	ch := cmp.NewChannel()

	go func() {
		ch.Send(Person{Name: "John Doe", Age: 30})
	}()

	msg := ch.Receive().(Person)
	fmt.Println("Message received:", msg)
}





/*
Example 10: Fan-Out Pattern with CMP Channels

Description:
This example demonstrates the fan-out pattern using CMP channels in Go.

Steps:
1. Create a CMP channel.
2. Start multiple goroutines (subscribers) to receive messages concurrently.
3. Send a message to the CMP channel to be received by all subscribers.

Expected Output:
Messages received:
- Subscriber 1 received: Hello, CMP!
- Subscriber 2 received: Hello, CMP!
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(2)

	for i := 1; i <= 2; i++ {
		go func(id int) {
			defer wg.Done()
			fmt.Printf("Subscriber %d received: %s\n", id, ch.Receive().(string))
		}(i)
	}

	ch.Send("Hello, CMP!")

	wg.Wait()
}





/*
Example 11: CMP Channel with Error Handling

Description:
This example demonstrates error handling using CMP channels in Go.

Steps:
1. Create a CMP channel.
2. Send a message containing an error.
3. Receive and handle the error message.

Expected Output:
Error received: Error: Something went wrong
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		ch.Send(fmt.Errorf("Error: Something went wrong"))
	}()

	err := ch.Receive().(error)
	fmt.Println("Error received:", err)
}





/*
Example 12: CMP Channel with Timeout and Default Value

Description:
This example demonstrates using CMP channels with timeout and default value handling in Go.

Steps:
1. Create a CMP channel.
2. Implement a select statement with timeout to handle message reception within a specified time.
3. Print received message or default value based on timeout.

Expected Output:
Message received: Hello, CMP! (if received within timeout)
Or
Default value: No message received within 1 second. (if timed out)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	select {
	case msg := <-ch.C:
		fmt.Println("Message received:", msg.(string))
	case <-time.After(1 * time.Second):
		fmt.Println("Default value: No message received within 1 second.")
	}
}





/*
Example 13: CMP Channel with Select Statement and Exit Signal

Description:
This example demonstrates using a CMP channel with a select statement and an exit signal in Go.

Steps:
1. Create a CMP channel.
2. Implement a goroutine to handle messages and an exit signal.
3. Use a select statement to receive messages or exit the goroutine.

Expected Output:
Messages received:
- Message: Hello, CMP! (if received before exit signal)
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		for {
			select {
			case msg := <-ch.C:
				fmt.Println("Message:", msg.(string))
			case <-time.After(1 * time.Second):
				fmt.Println("Timeout: No message received within 1 second.")
				return // Exit goroutine after timeout
			}
		}
	}()

	ch.Send("Hello, CMP!")

	time.Sleep(2 * time.Second) // Wait to see the output
}





/*
Example 14: CMP Channel with Goroutine Pool

Description:
This example demonstrates using a CMP channel with a goroutine pool in Go.

Steps:
1. Create a CMP channel.
2. Implement multiple goroutines in a pool to handle messages concurrently.
3. Send messages to the channel to be processed by the goroutine pool.

Expected Output:
Messages received:
- Worker 1 processed: Hello from CMP!
- Worker 2 processed: How are you?

Note: The order of messages processed may vary due to concurrency.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numWorkers = 2
	wg.Add(numWorkers)

	// Worker pool
	for i := 1; i <= numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				msg := ch.Receive().(string)
				fmt.Printf("Worker %d processed: %s\n", workerID, msg)
			}
		}(i)
	}

	// Send messages
	ch.Send("Hello from CMP!")
	ch.Send("How are you?")

	wg.Wait()
}





/*
Example 15: CMP Channel with Priority Queue

Description:
This example demonstrates using a CMP channel as a priority queue in Go.

Steps:
1. Create a CMP channel.
2. Implement goroutines with different priorities to handle messages.
3. Send messages with priorities to the channel.

Expected Output:
Messages processed based on priority:
- High priority message: Processing urgent task!
- Normal priority message: Processing regular task

Note: Messages with higher priorities are processed first.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

type Message struct {
	Text     string
	Priority int
}

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numWorkers = 2
	wg.Add(numWorkers)

	// Worker pool
	for i := 1; i <= numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				msg := ch.Receive().(Message)
				fmt.Printf("Worker %d processed: %s\n", workerID, msg.Text)
			}
		}(i)
	}

	// Send messages with priorities
	ch.Send(Message{Text: "Processing urgent task!", Priority: 1})
	ch.Send(Message{Text: "Processing regular task", Priority: 2})

	wg.Wait()
}





/*
Example 16: CMP Channel with Fan-In Pattern

Description:
This example demonstrates the fan-in pattern using CMP channels in Go.

Steps:
1. Create multiple CMP channels for input.
2. Implement a goroutine to multiplex messages from multiple channels into one output channel.
3. Receive and process messages from the output channel.

Expected Output:
Messages received:
- Message from Channel 1: Hello, CMP!
- Message from Channel 2: Hi, there!
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch1 := cmp.NewChannel()
	ch2 := cmp.NewChannel()

	outputCh := cmp.NewChannel()

	// Fan-in multiplexer
	go func() {
		for {
			select {
			case msg := <-ch1.C:
				outputCh.Send(fmt.Sprintf("Message from Channel 1: %s", msg.(string)))
			case msg := <-ch2.C:
				outputCh.Send(fmt.Sprintf("Message from Channel 2: %s", msg.(string)))
			}
		}
	}()

	ch1.Send("Hello, CMP!")
	ch2.Send("Hi, there!")

	fmt.Println("Messages received:")
	fmt.Println("- " + outputCh.Receive().(string))
	fmt.Println("- " + outputCh.Receive().(string))
}





/*
Example 17: CMP Channel with Rate Limiting

Description:
This example demonstrates using CMP channels with rate limiting in Go.

Steps:
1. Create a CMP channel.
2. Implement a goroutine to handle messages with rate limiting using time.Tick().
3. Send messages to the channel to be processed respecting the rate limit.

Expected Output:
Messages received with rate limiting applied:
- Message 1: Hello from CMP!
- Message 2: How are you?

Note: Messages are processed respecting the rate limit (one message per second).
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		ticker := time.Tick(1 * time.Second)
		messages := []string{"Hello from CMP!", "How are you?"}

		for _, msg := range messages {
			<-ticker
			ch.Send(msg)
		}
	}()

	fmt.Println("Messages received with rate limiting applied:")
	fmt.Println("- Message 1:", ch.Receive().(string))
	fmt.Println("- Message 2:", ch.Receive().(string))
}





/*
Example 18: CMP Channel with External Signal Handling

Description:
This example demonstrates using CMP channels to handle external signals in Go.

Steps:
1. Create a CMP channel for signals.
2. Implement a goroutine to wait for external signals (e.g., SIGINT).
3. Send a signal to the channel when the external signal is received.

Expected Output:
Signal received: Received SIGINT signal!
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT)

		// Wait for SIGINT signal
		<-sigCh
		ch.Send("Received SIGINT signal!")
	}()

	fmt.Println("Signal received:", ch.Receive().(string))
}





/*
Example 19: CMP Channel with Contextual Data

Description:
This example demonstrates using CMP channels with contextual data in Go.

Steps:
1. Create a CMP channel with context.
2. Send messages with contextual data.
3. Receive and process messages along with their context.

Expected Output:
Messages received with context:
- Context: {"userID": 123} Message: Hello, CMP!
*/

package main

import (
	"encoding/json"
	"fmt"
	"github.com/cmp/cmp"
)

type MessageWithCtx struct {
	Context map[string]interface{}
	Message string
}

func main() {
	ch := cmp.NewChannel()

	go func() {
		ctx := map[string]interface{}{"userID": 123}
		msg := MessageWithCtx{Context: ctx, Message: "Hello, CMP!"}
		ch.Send(msg)
	}()

	receivedMsg := ch.Receive().(MessageWithCtx)
	ctxJSON, _ := json.Marshal(receivedMsg.Context)

	fmt.Printf("Messages received with context:\n- Context: %s Message: %s\n", ctxJSON, receivedMsg.Message)
}





/*
Example 20: CMP Channel with Exponential Backoff Retry

Description:
This example demonstrates using CMP channels with exponential backoff retry mechanism in Go.

Steps:
1. Create a CMP channel for retries.
2. Implement a goroutine to handle retries with exponential backoff.
3. Send retry attempts to the channel and handle retries.

Expected Output:
Retrying attempt 1...
Retrying attempt 2...
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"math"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		maxAttempts := 5
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			waitTime := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			fmt.Printf("Retrying attempt %d...\n", attempt)
			time.Sleep(waitTime)
			ch.Send(fmt.Sprintf("Retry attempt %d", attempt))
		}
	}()

	for i := 1; i <= 2; i++ {
		fmt.Println(ch.Receive().(string))
	}
}





/*
Example 21: CMP Channel with Backpressure Handling

Description:
This example demonstrates using CMP channels with backpressure handling in Go.

Steps:
1. Create a CMP channel with a buffer size.
2. Implement a producer goroutine to send messages.
3. Implement a consumer goroutine to receive messages and apply backpressure if necessary.

Expected Output:
Messages sent and received with backpressure:
- Message 1: Hello from CMP!
- Message 2: How are you?

Note: The consumer processes messages with backpressure based on the buffer size.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewBufferedChannel(1)

	// Producer sending messages
	go func() {
		ch.Send("Hello from CMP!")
		ch.Send("How are you?")
	}()

	// Consumer receiving messages
	fmt.Println("Messages sent and received with backpressure:")
	fmt.Println("- Message 1:", ch.Receive().(string))
	fmt.Println("- Message 2:", ch.Receive().(string))

	// Simulate some processing time
	time.Sleep(1 * time.Second)

	// Check if there are more messages in the buffer
	for !ch.Empty() {
		fmt.Println("- Extra Message:", ch.Receive().(string))
	}
}





/*
Example 22: CMP Channel with Message Filtering

Description:
This example demonstrates using CMP channels with message filtering in Go.

Steps:
1. Create a CMP channel.
2. Implement a goroutine to filter and process specific types of messages.
3. Send messages to the channel and process filtered messages.

Expected Output:
Filtered messages processed:
- Filtered message: 42
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		ch.Send(42)
		ch.Send("Hello, CMP!")
		ch.Send(true)
	}()

	// Filter and process specific type of messages
	for {
		msg := ch.Receive()
		switch msg.(type) {
		case int:
			fmt.Println("Filtered message:", msg)
		}
		if ch.Empty() {
			break
		}
	}
}





/*
Example 23: CMP Channel with Task Distribution

Description:
This example demonstrates using CMP channels for task distribution among workers in Go.

Steps:
1. Create a CMP channel for task distribution.
2. Implement multiple worker goroutines to receive and process tasks concurrently.
3. Send tasks to the channel to be distributed and processed by the workers.

Expected Output:
Tasks distributed and processed by workers:
- Worker 1 processed task: Task 1
- Worker 2 processed task: Task 2

Note: Tasks are processed concurrently by multiple workers.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numWorkers = 2
	wg.Add(numWorkers)

	// Worker pool
	for i := 1; i <= numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				task := ch.Receive().(string)
				fmt.Printf("Worker %d processed task: %s\n", workerID, task)
				if ch.Empty() {
					break
				}
			}
		}(i)
	}

	// Send tasks
	ch.Send("Task 1")
	ch.Send("Task 2")

	wg.Wait()
}





/*
Example 24: CMP Channel with Batching

Description:
This example demonstrates using CMP channels for batching messages in Go.

Steps:
1. Create a CMP channel for batching.
2. Implement a goroutine to batch messages and send them in bulk.
3. Send individual messages to the channel to be batched and processed.

Expected Output:
Messages batched and processed:
- Batch 1: [Hello, CMP! How are you?]

Note: Messages are batched into slices and processed in bulk.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	// Batching goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var batch []interface{}
		for {
			msg := ch.Receive()
			batch = append(batch, msg)
			// Process batch every 2 seconds or when channel is empty
			if len(batch) >= 2 || ch.Empty() {
				fmt.Printf("Batch %d: %v\n", len(batch), batch)
				batch = nil // Clear batch
			}
			if ch.Empty() {
				break
			}
		}
		wg.Done()
	}()

	// Send messages
	ch.Send("Hello, CMP!")
	ch.Send("How are you?")

	wg.Wait()
}





/*
Example 25: CMP Channel with Error Recovery

Description:
This example demonstrates using CMP channels for error recovery in Go.

Steps:
1. Create a CMP channel for error recovery.
2. Implement a goroutine to handle errors and recover from them.
3. Send errors to the channel and handle recovery.

Expected Output:
Errors recovered and processed:
- Error: Something went wrong
- Recovered from error: Error handled successfully

Note: Errors are recovered and processed to ensure graceful error handling.
*/

package main

import (
	"errors"
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		err := errors.New("Something went wrong")
		ch.Send(err)
	}()

	// Handle errors and recovery
	for {
		err := ch.Receive()
		if err != nil {
			fmt.Println("Error:", err)
			fmt.Println("Recovered from error: Error handled successfully")
			break
		}
	}
}





/*
Example 26: CMP Channel with Timeout and Retry

Description:
This example demonstrates using CMP channels with timeout and retry mechanism in Go.

Steps:
1. Create a CMP channel for communication.
2. Implement a goroutine to send messages with potential delays.
3. Implement another goroutine to receive messages with timeout and retry if necessary.

Expected Output:
Messages sent and received with timeout and retry:
- Attempt 1: Hello, CMP!
- Attempt 2: How are you?

Note: Messages are sent with potential delays, and receiver retries with timeout if no message received.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	// Sender goroutine with delays
	go func() {
		time.Sleep(1 * time.Second)
		ch.Send("Hello, CMP!")

		time.Sleep(2 * time.Second)
		ch.Send("How are you?")
	}()

	// Receiver goroutine with timeout and retry
	fmt.Println("Messages sent and received with timeout and retry:")
	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case msg := <-ch.C:
			fmt.Printf("- Attempt %d: %s\n", attempt, msg.(string))
		case <-time.After(1 * time.Second):
			fmt.Printf("- Timeout: Retry attempt %d\n", attempt)
		}
	}
}





/*
Example 27: CMP Channel with Rate Limiting and Batching

Description:
This example demonstrates using CMP channels with rate limiting and batching in Go.

Steps:
1. Create a CMP channel for communication.
2. Implement a goroutine to send messages respecting a rate limit.
3. Implement another goroutine to receive and process batched messages.

Expected Output:
Messages sent and received with rate limiting and batching:
- Batch 1: [Hello from CMP! How are you?]

Note: Messages are sent respecting rate limit and processed in batches.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	// Sender goroutine respecting rate limit
	go func() {
		messages := []string{"Hello from CMP!", "How are you?"}
		for _, msg := range messages {
			ch.Send(msg)
			time.Sleep(1 * time.Second) // Rate limit of 1 message per second
		}
	}()

	// Receiver goroutine processing batched messages
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		var batch []string
		for {
			msg := ch.Receive().(string)
			batch = append(batch, msg)
			if len(batch) >= 2 || ch.Empty() {
				fmt.Printf("Batch %d: %v\n", len(batch), batch)
				batch = nil // Clear batch
			}
			if ch.Empty() {
				break
			}
		}
		wg.Done()
	}()

	wg.Wait()
}





/*
Example 28: CMP Channel with Worker Pool and Error Handling

Description:
This example demonstrates using CMP channels with a worker pool and error handling in Go.

Steps:
1. Create a CMP channel for task distribution.
2. Implement multiple worker goroutines to process tasks concurrently.
3. Send tasks to the channel and handle errors from workers.

Expected Output:
Tasks distributed and errors handled by workers:
- Worker 1 processed task: Task 1
- Worker 2 processed task: Task 2
- Error from Worker 2: Error: Task failed

Note: Tasks are processed concurrently by multiple workers, and errors are handled gracefully.
*/

package main

import (
	"errors"
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numWorkers = 2
	wg.Add(numWorkers)

	// Worker pool
	for i := 1; i <= numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				task := ch.Receive()
				fmt.Printf("Worker %d processed task: %s\n", workerID, task.(string))

				// Simulate task failure for Worker 2
				if workerID == 2 {
					ch.SendError(errors.New("Error: Task failed"))
				}

				if ch.Empty() {
					break
				}
			}
		}(i)
	}

	// Send tasks
	ch.Send("Task 1")
	ch.Send("Task 2")

	wg.Wait()
}





/*
Example 29: CMP Channel with Context Cancellation

Description:
This example demonstrates using CMP channels with context cancellation in Go.

Steps:
1. Create a CMP channel for task processing.
2. Implement a goroutine to process tasks with context.
3. Cancel context and handle cancellation gracefully.

Expected Output:
Tasks processed with context cancellation:
- Task 1 processed successfully
- Context canceled: Task 2 canceled due to context cancellation

Note: Tasks are processed with context, and cancellation is handled gracefully.
*/

package main

import (
	"context"
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	// Context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(2)

	// Worker 1 processing tasks
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Context canceled: Task 1 canceled due to context cancellation")
				return
			case <-time.After(1 * time.Second):
				ch.Send("Task 1 processed successfully")
			}
		}
	}()

	// Worker 2 processing tasks
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				fmt.Println("Context canceled: Task 2 canceled due to context cancellation")
				return
			case <-time.After(2 * time.Second):
				ch.Send("Task 2 processed successfully")
			}
		}
	}()

	// Simulate context cancellation after 3 seconds
	time.Sleep(3 * time.Second)
	cancel()

	wg.Wait()
}





/*
Example 30: CMP Channel with Selective Message Processing

Description:
This example demonstrates using CMP channels for selective message processing in Go.

Steps:
1. Create a CMP channel for message filtering.
2. Implement a goroutine to filter and process specific types of messages.
3. Send messages to the channel and process filtered messages.

Expected Output:
Selective messages processed:
- Message: Hello from CMP!

Note: Only messages of type string are processed, others are ignored.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch := cmp.NewChannel()

	go func() {
		ch.Send(42)
		ch.Send("Hello from CMP!")
		ch.Send(true)
	}()

	// Selective message processing
	for {
		msg := ch.Receive()
		switch msg.(type) {
		case string:
			fmt.Println("Selective message:", msg.(string))
		}
		if ch.Empty() {
			break
		}
	}
}





/*
Example 31: CMP Channel with Dynamic Worker Pool

Description:
This example demonstrates using CMP channels with a dynamic worker pool in Go.

Steps:
1. Create a CMP channel for task distribution.
2. Implement goroutines to dynamically add and remove workers based on task load.
3. Send tasks to the channel to be processed by the worker pool.

Expected Output:
Tasks distributed and processed by dynamic worker pool:
- Worker 1 processed task: Task 1
- Worker 2 processed task: Task 2

Note: Workers are dynamically added or removed based on the task load.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const maxWorkers = 3
	wg.Add(maxWorkers)

	// Dynamic worker pool
	for i := 1; i <= maxWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				task := ch.Receive()
				if task == nil {
					break
				}
				fmt.Printf("Worker %d processed task: %s\n", workerID, task.(string))
			}
			fmt.Printf("Worker %d stopped\n", workerID)
		}(i)
	}

	// Send tasks
	ch.Send("Task 1")
	ch.Send("Task 2")

	// Simulate adding more tasks
	ch.Send("Task 3")
	ch.Send("Task 4")

	// Close channel to signal no more tasks
	ch.Close()

	wg.Wait()
}





/*
Example 32: CMP Channel with Request-Response Pattern

Description:
This example demonstrates using CMP channels for implementing a request-response pattern in Go.

Steps:
1. Create a CMP channel for handling requests.
2. Implement goroutines to handle incoming requests and send responses.
3. Send requests to the channel and process responses.

Expected Output:
Requests processed with responses:
- Request: GetInfo Response: Information retrieved successfully

Note: Requests are processed, and responses are sent back via CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Request handler goroutine
	go func() {
		defer wg.Done()
		for {
			request := ch.Receive().(string)
			if request == "GetInfo" {
				ch.Send("Information retrieved successfully")
			} else if request == "GetData" {
				ch.Send("Data retrieved successfully")
			}
		}
	}()

	// Send request and process response
	ch.Send("GetInfo")
	fmt.Printf("Request: GetInfo Response: %s\n", ch.Receive().(string))

	// Optional: Send more requests
	ch.Send("GetData")
	fmt.Printf("Request: GetData Response: %s\n", ch.Receive().(string))

	// Close channel to signal end
	ch.Close()

	wg.Wait()
}





/*
Example 33: CMP Channel with Multi-Channel Communication

Description:
This example demonstrates using multiple CMP channels for communication in Go.

Steps:
1. Create multiple CMP channels for different types of messages.
2. Implement goroutines to handle messages from each channel.
3. Send messages to the channels and process them accordingly.

Expected Output:
Messages processed from multiple channels:
- Channel 1 message: Hello, CMP!
- Channel 2 message: How are you?

Note: Messages are processed based on their respective channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
)

func main() {
	ch1 := cmp.NewChannel()
	ch2 := cmp.NewChannel()

	// Goroutine handling messages from Channel 1
	go func() {
		msg := ch1.Receive().(string)
		fmt.Println("Channel 1 message:", msg)
	}()

	// Goroutine handling messages from Channel 2
	go func() {
		msg := ch2.Receive().(string)
		fmt.Println("Channel 2 message:", msg)
	}()

	// Send messages to respective channels
	ch1.Send("Hello, CMP!")
	ch2.Send("How are you?")

	// Optionally, close channels if no more messages
	ch1.Close()
	ch2.Close()
}





/*
Example 34: CMP Channel with Graceful Shutdown

Description:
This example demonstrates using CMP channels for implementing graceful shutdown in Go.

Steps:
1. Create a CMP channel for handling tasks.
2. Implement goroutines to handle tasks and wait for shutdown signal.
3. Send tasks to the channel and perform cleanup on shutdown.

Expected Output:
Tasks processed with graceful shutdown:
- Task 1 processed successfully
- Task 2 processed successfully
- Shutdown signal received: Cleaning up resources...

Note: Tasks are processed, and cleanup is performed upon receiving shutdown signal.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Task handler goroutine
	go func() {
		defer wg.Done()
		for {
			select {
			case task := <-ch.C:
				fmt.Printf("Task %s processed successfully\n", task.(string))
			case <-ch.Done():
				fmt.Println("Shutdown signal received: Cleaning up resources...")
				return
			}
		}
	}()

	// Send tasks
	ch.Send("Task 1")
	ch.Send("Task 2")

	// Simulate some task processing time
	time.Sleep(2 * time.Second)

	// Send shutdown signal
	ch.Close()

	wg.Wait()
}





/*
Example 35: CMP Channel with Broadcast Pattern

Description:
This example demonstrates using CMP channels for implementing a broadcast pattern in Go.

Steps:
1. Create a CMP channel for broadcasting messages.
2. Implement goroutines to handle subscribers and broadcast messages.
3. Subscribe to the channel and receive broadcasted messages.

Expected Output:
Messages broadcasted and received by subscribers:
- Subscriber 1 received message: Hello from CMP!
- Subscriber 2 received message: How are you?

Note: Messages are broadcasted to all subscribers listening to the channel.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numSubscribers = 2
	wg.Add(numSubscribers)

	// Subscriber goroutines
	for i := 1; i <= numSubscribers; i++ {
		go func(subscriberID int) {
			defer wg.Done()
			for {
				msg := ch.Receive().(string)
				fmt.Printf("Subscriber %d received message: %s\n", subscriberID, msg)
			}
		}(i)
	}

	// Broadcast messages
	ch.Send("Hello from CMP!")
	ch.Send("How are you?")

	// Optionally, close channel if no more broadcasts
	ch.Close()

	wg.Wait()
}





/*
Example 36: CMP Channel with Priority Queue

Description:
This example demonstrates using CMP channels to implement a priority queue in Go.

Steps:
1. Create a CMP channel with multiple channels for different priority levels.
2. Implement goroutines to handle tasks from each priority channel.
3. Send tasks to the appropriate priority channel and process them based on priority.

Expected Output:
Tasks processed from priority queues:
- High Priority Task: Handle urgent request
- Medium Priority Task: Process important data
- Low Priority Task: Log routine activity

Note: Tasks are processed based on their priority levels using separate channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	highPriority := cmp.NewChannel()
	mediumPriority := cmp.NewChannel()
	lowPriority := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(3)

	// High priority tasks handler
	go func() {
		defer wg.Done()
		for {
			task := highPriority.Receive().(string)
			fmt.Println("High Priority Task:", task)
		}
	}()

	// Medium priority tasks handler
	go func() {
		defer wg.Done()
		for {
			task := mediumPriority.Receive().(string)
			fmt.Println("Medium Priority Task:", task)
		}
	}()

	// Low priority tasks handler
	go func() {
		defer wg.Done()
		for {
			task := lowPriority.Receive().(string)
			fmt.Println("Low Priority Task:", task)
		}
	}()

	// Send tasks to respective priority channels
	highPriority.Send("Handle urgent request")
	mediumPriority.Send("Process important data")
	lowPriority.Send("Log routine activity")

	// Optionally, close channels if no more tasks
	highPriority.Close()
	mediumPriority.Close()
	lowPriority.Close()

	wg.Wait()
}





/*
Example 37: CMP Channel with Rate Limiting and Timeout

Description:
This example demonstrates using CMP channels with rate limiting and timeout handling in Go.

Steps:
1. Create a CMP channel for message handling.
2. Implement a goroutine to send messages with rate limiting.
3. Implement another goroutine to receive messages with timeout and retry mechanism.

Expected Output:
Messages sent and received with rate limiting and timeout:
- Message received: Hello from CMP!
- Timeout: No response received within 1 second

Note: Messages are sent respecting rate limit and handled with timeout and retry mechanism.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	// Sender goroutine with rate limiting
	go func() {
		for i := 1; i <= 3; i++ {
			ch.Send(fmt.Sprintf("Message %d", i))
			time.Sleep(1 * time.Second) // Rate limit of 1 message per second
		}
	}()

	// Receiver goroutine with timeout and retry
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-ch.C:
				fmt.Println("Message received:", msg.(string))
			case <-time.After(2 * time.Second):
				fmt.Println("Timeout: No response received within 2 seconds")
				return
			}
		}
	}()

	wg.Wait()
}





/*
Example 38: CMP Channel with Event Subscription

Description:
This example demonstrates using CMP channels for event subscription and handling in Go.

Steps:
1. Create a CMP channel for event handling.
2. Implement goroutines to subscribe to events and handle them.
3. Send events to the channel and process them based on subscriptions.

Expected Output:
Events subscribed and processed:
- Subscriber 1 received event: User logged in
- Subscriber 2 received event: Data updated

Note: Events are subscribed and processed by multiple subscribers using CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numSubscribers = 2
	wg.Add(numSubscribers)

	// Subscriber goroutines
	for i := 1; i <= numSubscribers; i++ {
		go func(subscriberID int) {
			defer wg.Done()
			for {
				event := ch.Receive().(string)
				fmt.Printf("Subscriber %d received event: %s\n", subscriberID, event)
			}
		}(i)
	}

	// Send events to the channel
	ch.Send("User logged in")
	ch.Send("Data updated")

	// Optionally, close channel if no more events
	ch.Close()

	wg.Wait()
}





/*
Example 39: CMP Channel with Load Balancing

Description:
This example demonstrates using CMP channels for load balancing among workers in Go.

Steps:
1. Create a CMP channel for task distribution.
2. Implement multiple worker goroutines to receive and process tasks concurrently.
3. Send tasks to the channel to be load balanced and processed by the workers.

Expected Output:
Tasks load balanced and processed by workers:
- Worker 1 processed task: Task 1
- Worker 2 processed task: Task 2

Note: Tasks are load balanced among workers, ensuring efficient processing using CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numWorkers = 2
	wg.Add(numWorkers)

	// Worker pool for load balancing
	for i := 1; i <= numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for {
				task := ch.Receive()
				if task == nil {
					break
				}
				fmt.Printf("Worker %d processed task: %s\n", workerID, task.(string))
			}
		}(i)
	}

	// Send tasks to be load balanced
	ch.Send("Task 1")
	ch.Send("Task 2")

	// Optionally, close channel if no more tasks
	ch.Close()

	wg.Wait()
}





/*
Example 40: CMP Channel with Message Deduplication

Description:
This example demonstrates using CMP channels for message deduplication in Go.

Steps:
1. Create a CMP channel for receiving messages.
2. Implement goroutines to deduplicate incoming messages.
3. Send messages to the channel and process them while ensuring deduplication.

Expected Output:
Deduplicated messages processed:
- Message received: Hello from CMP!

Note: Incoming messages are deduplicated before processing using CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	dedup := make(map[string]bool)
	var mu sync.Mutex

	// Deduplication goroutine
	go func() {
		for {
			msg := ch.Receive().(string)

			mu.Lock()
			if !dedup[msg] {
				dedup[msg] = true
				fmt.Println("Message received:", msg)
			}
			mu.Unlock()
		}
	}()

	// Send messages with potential duplicates
	ch.Send("Hello from CMP!")
	ch.Send("Hello from CMP!") // Duplicate message
	ch.Send("How are you?")

	// Optionally, close channel if no more messages
	ch.Close()
}





/*
Example 41: CMP Channel with Fan-In Pattern

Description:
This example demonstrates using CMP channels to implement a fan-in pattern in Go.

Steps:
1. Create multiple CMP channels for producers to send data.
2. Implement a goroutine to merge data from multiple channels into a single channel.
3. Receive merged data from the fan-in channel and process it.

Expected Output:
Data merged and processed using fan-in pattern:
- Data received from Channel 1: Hello, CMP!
- Data received from Channel 2: How are you?

Note: Data from multiple channels is merged into a single channel using the fan-in pattern.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch1 := cmp.NewChannel()
	ch2 := cmp.NewChannel()

	fanIn := cmp.MergeChannels(ch1, ch2)

	var wg sync.WaitGroup
	wg.Add(1)

	// Receiver goroutine for merged data
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-fanIn.C:
				fmt.Printf("Data received from Channel %d: %s\n", msg.(int), fanIn.Receive().(string))
			case <-fanIn.Done():
				fmt.Println("Fan-in channel closed.")
				return
			}
		}
	}()

	// Send data to respective channels
	ch1.Send("Hello, CMP!")
	ch2.Send("How are you?")

	// Optionally, close channels if no more data
	ch1.Close()
	ch2.Close()

	wg.Wait()
}





/*
Example 42: CMP Channel with Pub/Sub Pattern

Description:
This example demonstrates using CMP channels to implement a pub/sub (publish/subscribe) pattern in Go.

Steps:
1. Create a CMP channel for pub/sub communication.
2. Implement goroutines for publishers to publish messages to topics.
3. Implement goroutines for subscribers to receive messages from topics.

Expected Output:
Messages published and subscribed using pub/sub pattern:
- Subscriber 1 received message from Topic 1: Hello from CMP!
- Subscriber 2 received message from Topic 2: How are you?

Note: Messages are published to topics and received by subscribers using CMP channels for pub/sub communication.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	// Subscriber 1
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-ch.C:
				fmt.Printf("Subscriber 1 received message from Topic 1: %s\n", msg.(string))
			case <-ch.Done():
				fmt.Println("Subscriber 1 channel closed.")
				return
			}
		}
	}()

	// Subscriber 2
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg := <-ch.C:
				fmt.Printf("Subscriber 2 received message from Topic 2: %s\n", msg.(string))
			case <-ch.Done():
				fmt.Println("Subscriber 2 channel closed.")
				return
			}
		}
	}()

	// Publisher 1 publishing to Topic 1
	go func() {
		ch.SendTo("Hello from CMP!", 1)
	}()

	// Publisher 2 publishing to Topic 2
	go func() {
		ch.SendTo("How are you?", 2)
	}()

	// Optionally, close channel if no more messages
	ch.Close()

	wg.Wait()
}





/*
Example 43: CMP Channel with Circuit Breaker Pattern

Description:
This example demonstrates using CMP channels to implement a circuit breaker pattern in Go.

Steps:
1. Create a CMP channel for communication with circuit breaker logic.
2. Implement goroutines to handle requests and monitor failures.
3. Send requests to the channel and manage circuit state (open/closed/half-open).

Expected Output:
Requests processed and circuit state managed using circuit breaker pattern:
- Request successful: Data retrieved successfully
- Circuit breaker open: Service unavailable, circuit open
- Circuit breaker closed: Retry request after some time

Note: Requests are processed with circuit breaker logic to manage service availability using CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

func main() {
	ch := cmp.NewChannel()

	var circuitOpen bool
	var wg sync.WaitGroup
	wg.Add(1)

	// Request handler with circuit breaker
	go func() {
		defer wg.Done()
		for {
			select {
			case req := <-ch.C:
				if circuitOpen {
					fmt.Println("Circuit breaker open: Service unavailable, circuit open")
				} else {
					if requestSuccessful() {
						fmt.Println("Request successful:", req.(string))
					} else {
						fmt.Println("Request failed: Retry after some time")
						circuitOpen = true
						go resetCircuitBreaker(&circuitOpen)
					}
				}
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Simulate requests
	ch.Send("Data retrieved successfully")
	ch.Send("Data retrieval failed")

	// Optionally, close channel if no more requests
	ch.Close()

	wg.Wait()
}

func requestSuccessful() bool {
	// Simulate request success/failure
	return time.Now().UnixNano()%2 == 0 // 50% chance of success
}

func resetCircuitBreaker(circuitOpen *bool) {
	time.Sleep(5 * time.Second) // Reset circuit breaker after 5 seconds
	*circuitOpen = false
}





/*
Example 44: CMP Channel with State Machine

Description:
This example demonstrates using CMP channels to implement a state machine in Go.

Steps:
1. Create a CMP channel for state transitions and actions.
2. Implement goroutines to handle state transitions and execute actions.
3. Send events to the channel to trigger state changes and actions.

Expected Output:
State transitions executed and actions performed using state machine:
- State A: Event 1 received, transition to State B
- State B: Event 2 received, perform Action X

Note: State transitions are managed using CMP channels, triggering actions based on current state.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

type State string

const (
	StateA State = "State A"
	StateB State = "State B"
)

func main() {
	ch := cmp.NewChannel()

	var currentState State = StateA
	var wg sync.WaitGroup
	wg.Add(1)

	// State machine handler
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-ch.C:
				switch currentState {
				case StateA:
					fmt.Printf("%s: %s received, transition to %s\n", currentState, event.(string), StateB)
					currentState = StateB
					ch.Send("Event 2")
				case StateB:
					fmt.Printf("%s: %s received, perform Action X\n", currentState, event.(string))
					// Perform Action X
					currentState = StateA
					ch.Send("Event 1")
				}
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Start state machine with initial event
	ch.Send("Event 1")

	// Optionally, close channel if no more events
	ch.Close()

	wg.Wait()
}





/*
Example 45: CMP Channel with Feedback Control Loop

Description:
This example demonstrates using CMP channels to implement a feedback control loop in Go.

Steps:
1. Create a CMP channel for feedback control and adjustment.
2. Implement goroutines to monitor and adjust parameters based on feedback.
3. Send feedback to the channel and adjust parameters accordingly.

Expected Output:
Parameters adjusted based on feedback using feedback control loop:
- Adjusted parameter: Threshold increased to 80

Note: Parameters are monitored and adjusted dynamically based on feedback using CMP channels.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

type ControlParameters struct {
	Threshold int
}

func main() {
	ch := cmp.NewChannel()

	params := &ControlParameters{
		Threshold: 75,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Feedback control loop handler
	go func() {
		defer wg.Done()
		for {
			select {
			case feedback := <-ch.C:
				fmt.Printf("Feedback received: %s\n", feedback.(string))
				// Adjust parameters based on feedback
				params.Threshold += 5
				fmt.Printf("Adjusted parameter: Threshold increased to %d\n", params.Threshold)
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Send feedback to adjust parameters
	ch.Send("Increase threshold")

	// Optionally, close channel if no more feedback
	ch.Close()

	wg.Wait()
}





/*
Example 46: CMP Channel with Leader Election

Description:
This example demonstrates using CMP channels to implement leader election in a distributed system using Go.

Steps:
1. Create a CMP channel for nodes to participate in leader election.
2. Implement goroutines for nodes to send heartbeats and participate in election.
3. Monitor the channel for leader announcements and handle leader election logic.

Expected Output:
Nodes participate in leader election and elect a leader:
- Node 1 elected as leader
- Node 2 elected as leader

Note: Nodes send heartbeats and participate in leader election using CMP channels in a distributed system.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
	"time"
)

type Node struct {
	ID     int
	Leader bool
}

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numNodes = 3
	wg.Add(numNodes)

	// Node goroutines for leader election
	for i := 1; i <= numNodes; i++ {
		node := Node{ID: i}

		go func(n Node) {
			defer wg.Done()

			// Send initial heartbeat
			ch.Send(fmt.Sprintf("Node %d: Heartbeat", n.ID))

			for {
				select {
				case msg := <-ch.C:
					fmt.Printf("Node %d received: %s\n", n.ID, msg.(string))

					// Election logic example: Node with highest ID becomes leader
					if !n.Leader {
						n.Leader = true
						ch.Send(fmt.Sprintf("Node %d elected as leader", n.ID))
					}
				case <-time.After(5 * time.Second):
					// Send heartbeat periodically
					ch.Send(fmt.Sprintf("Node %d: Heartbeat", n.ID))
				case <-ch.Done():
					fmt.Printf("Node %d channel closed.\n", n.ID)
					return
				}
			}
		}(node)
	}

	// Wait for leader election to finish
	wg.Wait()

	// Optionally, close channel if no more activities
	ch.Close()
}





/*
Example 47: CMP Channel with Data Stream Processing

Description:
This example demonstrates using CMP channels for processing data streams in Go.

Steps:
1. Create a CMP channel for data stream processing.
2. Implement goroutines to handle incoming data and process it.
3. Send data to the channel and process it in real-time.

Expected Output:
Data streams processed in real-time using CMP channels:
- Data processed: Sensor reading received: 25.5
- Data processed: Event logged: User logged in

Note: Data streams are processed in real-time using CMP channels for efficient data handling.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

type Data struct {
	Type    string
	Payload interface{}
}

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Data processor goroutine
	go func() {
		defer wg.Done()
		for {
			select {
			case data := <-ch.C:
				d := data.(Data)
				switch d.Type {
				case "Sensor":
					fmt.Printf("Data processed: Sensor reading received: %.1f\n", d.Payload.(float64))
				case "Event":
					fmt.Printf("Data processed: Event logged: %s\n", d.Payload.(string))
				}
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Send data to process
	ch.Send(Data{Type: "Sensor", Payload: 25.5})
	ch.Send(Data{Type: "Event", Payload: "User logged in"})

	// Optionally, close channel if no more data
	ch.Close()

	wg.Wait()
}





/*
Example 48: CMP Channel with Error Handling

Description:
This example demonstrates using CMP channels for error handling and recovery in Go.

Steps:
1. Create a CMP channel for handling tasks with error handling logic.
2. Implement goroutines to handle tasks and recover from errors.
3. Send tasks to the channel and handle errors gracefully.

Expected Output:
Tasks processed with error handling and recovery using CMP channels:
- Task processed: Task 1 completed successfully
- Task processed: Task 2 failed: Error: Task 2 failed due to network issue

Note: Tasks are processed with error handling and recovery logic using CMP channels for robust application behavior.
*/

package main

import (
	"errors"
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	var wg sync.WaitGroup
	const numTasks = 2
	wg.Add(numTasks)

	// Task handler goroutine with error handling
	go func() {
		defer wg.Done()
		for {
			select {
			case task := <-ch.C:
				if err := processTask(task.(string)); err != nil {
					fmt.Printf("Task processed: %s failed: Error: %s\n", task.(string), err.Error())
				} else {
					fmt.Printf("Task processed: %s completed successfully\n", task.(string))
				}
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Send tasks to process
	ch.Send("Task 1")
	ch.Send("Task 2")

	// Optionally, close channel if no more tasks
	ch.Close()

	wg.Wait()
}

func processTask(task string) error {
	// Simulate task processing with potential errors
	if task == "Task 2" {
		return errors.New("Task 2 failed due to network issue")
	}
	return nil
}





/*
Example 49: CMP Channel with Resource Pooling

Description:
This example demonstrates using CMP channels to implement resource pooling in Go.

Steps:
1. Create a CMP channel for managing resources.
2. Implement goroutines to acquire and release resources from the pool.
3. Send requests to the channel to acquire and release resources.

Expected Output:
Resources acquired and released using CMP channels for resource pooling:
- Resource acquired: Connection 1
- Resource released: Connection 1

Note: Resources are managed efficiently using CMP channels for resource pooling in concurrent applications.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

func main() {
	ch := cmp.NewChannel()

	const poolSize = 2
	var wg sync.WaitGroup
	wg.Add(poolSize)

	// Resource pool goroutine
	for i := 1; i <= poolSize; i++ {
		resourceID := fmt.Sprintf("Connection %d", i)

		go func(id string) {
			defer wg.Done()

			// Acquire resource
			ch.Send(fmt.Sprintf("Resource acquired: %s", id))

			// Simulate resource usage
			// ...

			// Release resource
			ch.Send(fmt.Sprintf("Resource released: %s", id))
		}(resourceID)
	}

	// Optionally, close channel if no more resource operations
	ch.Close()

	wg.Wait()
}





/*
Example 50: CMP Channel with Cache Implementation

Description:
This example demonstrates using CMP channels to implement a cache in Go.

Steps:
1. Create a CMP channel for managing cached data.
2. Implement goroutines to handle cache operations (get, set, delete).
3. Send cache operations to the channel and manage cached data.

Expected Output:
Cache operations performed using CMP channels:
- Cache item added: key: "user-1", value: "{name: John, age: 30}"
- Cache item deleted: key: "user-1"

Note: Cached data is managed efficiently using CMP channels for common cache operations in applications.
*/

package main

import (
	"fmt"
	"github.com/cmp/cmp"
	"sync"
)

type CacheOperation struct {
	Type  string // "add", "get", "delete"
	Key   string
	Value interface{}
}

func main() {
	ch := cmp.NewChannel()

	cache := make(map[string]interface{})
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(1)

	// Cache handler goroutine
	go func() {
		defer wg.Done()
		for {
			select {
			case op := <-ch.C:
				switch operation := op.(CacheOperation); operation.Type {
				case "add":
					mu.Lock()
					cache[operation.Key] = operation.Value
					mu.Unlock()
					fmt.Printf("Cache item added: key: %q, value: %v\n", operation.Key, operation.Value)
				case "get":
					mu.Lock()
					value, found := cache[operation.Key]
					mu.Unlock()
					if found {
						fmt.Printf("Cache item found: key: %q, value: %v\n", operation.Key, value)
					} else {
						fmt.Printf("Cache item not found: key: %q\n", operation.Key)
					}
				case "delete":
					mu.Lock()
					delete(cache, operation.Key)
					mu.Unlock()
					fmt.Printf("Cache item deleted: key: %q\n", operation.Key)
				}
			case <-ch.Done():
				fmt.Println("Channel closed.")
				return
			}
		}
	}()

	// Perform cache operations
	ch.Send(CacheOperation{Type: "add", Key: "user-1", Value: map[string]interface{}{"name": "John", "age": 30}})
	ch.Send(CacheOperation{Type: "get", Key: "user-1"})
	ch.Send(CacheOperation{Type: "delete", Key: "user-1"})

	// Optionally, close channel if no more cache operations
	ch.Close()

	wg.Wait()
}












//Initialize a new cobra application : 

package main

import (
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "app"}
	rootCmd.Execute()
}


// Add a version Command

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of the app",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("App v0.1")
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.Execute()
}


// Add a help Command

package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	rootCmd.InitDefaultHelpCmd()
	rootCmd.Execute()
}



//Add custom command with arguments 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// Add a persistent flag

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd   = &cobra.Command{Use: "app"}
	echoCmd   = &cobra.Command{Use: "echo [message]", Short: "Echo the provided message", Args: cobra.MinimumNArgs(1), Run: echoRun}
	rootName  string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&rootName, "name", "n", "World", "name to greet")
	rootCmd.AddCommand(echoCmd)
}

func echoRun(cmd *cobra.Command, args []string) {
	fmt.Printf("Hello, %s!\n", rootName)
}

func main() {
	rootCmd.Execute()
}



// Add a local flag 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd   = &cobra.Command{Use: "app"}
	echoCmd   = &cobra.Command{Use: "echo [message]", Short: "Echo the provided message", Args: cobra.MinimumNArgs(1), Run: echoRun}
	echoTimes int
)

func init() {
	echoCmd.Flags().IntVarP(&echoTimes, "times", "t", 1, "number of times to echo the message")
	rootCmd.AddCommand(echoCmd)
}

func echoRun(cmd *cobra.Command, args []string) {
	for i := 0; i < echoTimes; i++ {
		fmt.Println(args[0])
	}
}

func main() {
	rootCmd.Execute()
}



//Adds a command with subcommands 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{Use: "app"}
)

func init() {
	var addCmd = &cobra.Command{Use: "add", Short: "Add items"}
	var sumCmd = &cobra.Command{Use: "sum", Short: "Sum items"}
	var listCmd = &cobra.Command{Use: "list", Short: "List items"}

	addCmd.AddCommand(sumCmd, listCmd)
	rootCmd.AddCommand(addCmd)
}

func main() {
	rootCmd.Execute()
}



// Uses pre-run and post-run hooks 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{Use: "app"}
)

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			fmt.Println("Preparing to echo...")
		},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			fmt.Println("Echo complete.")
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Adds completion support  : 


package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.InitDefaultCompletionCmd()
}

func main() {
	rootCmd.Execute()
}



// Defines a custom usage template 

package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.SetUsageTemplate(`Usage:
  {{.UseLine}}
  
{{if .HasAvailableSubCommands}}{{.Commands}}{{end}}`)
}

func main() {
	rootCmd.Execute()
}



// Code to use annotations in commands 


package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
		Annotations: map[string]string{"group": "utility"},
	}

	rootCmd.AddCommand(echoCmd)
}

func main() {
	rootCmd.Execute()
}




// Code to use commands aliases 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	var echoCmd = &cobra.Command{
		Use:     "echo [message]",
		Aliases: []string{"say", "repeat"},
		Short:   "Echo the provided message",
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
}

func main() {
	rootCmd.Execute()
}


// Code to disaply command usage : 


package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	echoCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println("This is a custom help message for the echo command.")
	})

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Code to define command groups : 

package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	var addCmd = &cobra.Command{Use: "add", Short: "Add items"}
	var sumCmd = &cobra.Command{Use: "sum", Short: "Sum items"}
	var listCmd = &cobra.Command{Use: "list", Short: "List items"}

	addCmd.AddCommand(sumCmd, listCmd)
	rootCmd.AddCommand(addCmd)
}

func main() {
	rootCmd.Execute()
}




// Code to mark a flag as required : 


package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	rootCmd   = &cobra.Command{Use: "app"}
	echoCmd   = &cobra.Command{Use: "echo [message]", Short: "Echo the provided message", Args: cobra.MinimumNArgs(1), Run: echoRun}
	echoTimes int
)

func init() {
	echoCmd.Flags().IntVarP(&echoTimes, "times", "t", 0, "number of times to echo the message")
	echoCmd.MarkFlagRequired("times")
	rootCmd.AddCommand(echoCmd)
}

func echoRun(cmd *cobra.Command, args []string) {
	for i := 0; i < echoTimes; i++ {
		fmt.Println(args[0])
	}
}

func main() {
	rootCmd.Execute()
}



// Code to use Cobra's Args package : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Code to customize usage function 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Println("This is a custom usage message.")
		return nil
	})
}

func main() {
	rootCmd.Execute()
}




// Code to use custom error handling : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	rootCmd.Execute()
}

func init() {
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running persistent pre-run command")
		return nil
	}
	rootCmd.PersistentPostRunE = func(cmd *cobra.Command, args []string) error {
		fmt.Println("Running persistent post-run command")
		return nil
	}
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help",
		Short: "Help for the app",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("this is a custom error")
		},
	})
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		fmt.Println("Custom flag error message")
		return err
	})
	rootCmd.SetArgs(os.Args[1:])
}



// COde to Add a persistent pre-run command

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		fmt.Println("This runs before any command.")
	}
}

func main() {
	rootCmd.Execute()
}



// Code to add persistent post-run command : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
		fmt.Println("This runs after any command.")
	}
}

func main() {
	rootCmd.Execute()
}




// Code to Use variable argument functions

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [messages...]",
		Short: "Echo the provided messages",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			for _, arg := range args {
				fmt.Println(arg)
			}
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Code to chain commands together : 


package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	var upperCmd = &cobra.Command{
		Use:   "upper [message]",
		Short: "Echo the provided message in uppercase",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(strings.ToUpper(args[0]))
		},
	}

	rootCmd.AddCommand(echoCmd)
	echoCmd.AddCommand(upperCmd)
	rootCmd.Execute()
}




// Override default help command 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help",
		Short: "Show custom help for the app",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("This is a custom help message.")
		},
	})
}

func main() {
	rootCmd.Execute()
}


// Code to persist a configuration file : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file: %v\n", err)
	}
}

func main() {
	rootCmd.Execute()
}


// code to print command line flags : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Flags().VisitAll(func(f *cobra.Flag) {
				fmt.Printf("%s: %s\n", f.Name, f.Value)
			})
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Code to run commands in sequence : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Flags().VisitAll(func(f *cobra.Flag) {
				fmt.Printf("%s: %s\n", f.Name, f.Value)
			})
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Go code to Chain flag values

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var times int
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			for i := 0; i < times; i++ {
				fmt.Println(args[0])
			}
		},
	}

	echoCmd.Flags().IntVarP(&times, "times", "t", 1, "number of times to echo the message")
	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// code to Get flag values directly

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var times int
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			times, _ = cmd.Flags().GetInt("times")
			for i := 0; i < times; i++ {
				fmt.Println(args[0])
			}
		},
	}

	echoCmd.Flags().IntVarP(&times, "times", "t", 1, "number of times to echo the message")
	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// Go code to generate bash completions : 


package main

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var completionCmd = &cobra.Command{
		Use:   "completion",
		Short: "Generate bash completion script",
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenBashCompletion(os.Stdout)
		},
	}

	rootCmd.AddCommand(completionCmd)
	rootCmd.Execute()
}




// code to Generate Zsh completions : 

package main

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var completionCmd = &cobra.Command{
		Use:   "completion",
		Short: "Generate zsh completion script",
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenZshCompletion(os.Stdout)
		},
	}

	rootCmd.AddCommand(completionCmd)
	rootCmd.Execute()
}



// code to use command with persistent flags 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	echoCmd.PersistentFlags().String("prefix", "", "prefix message")
	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// Code to pass arguments to subcommands 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	var repeatCmd = &cobra.Command{
		Use:   "repeat [times] [message]",
		Short: "Repeat the provided message a number of times",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			times := args[0]
			message := args[1]
			fmt.Printf("%s repeated %s times\n", message, times)
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.AddCommand(repeatCmd)
	rootCmd.Execute()
}




// Go code to use shorthand for commands 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:     "echo [message]",
		Short:   "Echo the provided message",
		Aliases: []string{"e"},
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// code to add dynamic flags 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"strconv"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			times, _ := strconv.Atoi(args[0])
			message := args[1]
			for i := 0; i < times; i++ {
				fmt.Println(message)
			}
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Code to override global flags 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var verbose bool
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if verbose {
				fmt.Println("Verbose mode enabled")
			}
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}


// Go code to use built-in root command :

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}




// Go code to use custom version command : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.Version = "1.0.0"
}

func main() {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of the app",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("App v1.0.0")
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.Execute()
}



// GO code to use command groups

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(args[0])
		},
	}

	var repeatCmd = &cobra.Command{
		Use:   "repeat [message]",
		Short: "Repeat the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			for i := 0; i < 2; i++ {
				fmt.Println(args[0])
			}
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.AddCommand(repeatCmd)
	rootCmd.Execute()
}



// Code to use dynaic argument parsing : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [messages...]",
		Short: "Echo the provided messages",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			for _, arg := range args {
				fmt.Println(arg)
			}
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// code to use persistent flag values 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var prefix string
	rootCmd.PersistentFlags().StringVarP(&prefix, "prefix", "p", "", "prefix message")

	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(prefix + args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// go code to use context in commands : 

package main

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			message := args[0]
			fmt.Println("Context:", ctx)
			fmt.Println("Message:", message)
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.ExecuteContext(context.Background())
}




// go code to use silent errors : 

package main

import (
	"errors"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var errorCmd = &cobra.Command{
		Use:   "error",
		Short: "Generate an error",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("this is a silent error")
		},
		SilenceErrors: true,
	}

	rootCmd.AddCommand(errorCmd)
	rootCmd.Execute()
}



// go code to use silent usage : 

package main

import (
	"errors"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var errorCmd = &cobra.Command{
		Use:   "error",
		Short: "Generate an error",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("this is a silent error")
		},
		SilenceUsage: true,
	}

	rootCmd.AddCommand(errorCmd)
	rootCmd.Execute()
}



// go code to print the version of the application 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var version string

var rootCmd = &cobra.Command{Use: "app"}

func init() {
	rootCmd.Version = version
}

func main() {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of the app",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("App version: %s\n", version)
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.Execute()
}


// go code to use variable argument count 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var sumCmd = &cobra.Command{
		Use:   "sum [numbers...]",
		Short: "Sum the provided numbers",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sum := 0
			for _, arg := range args {
				var num int
				fmt.Sscanf(arg, "%d", &num)
				sum += num
			}
			fmt.Println("Sum:", sum)
		},
	}

	rootCmd.AddCommand(sumCmd)
	rootCmd.Execute()
}



// go code to use custom output 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.SetOut(os.Stdout)
			cmd.Println(args[0])
		},
	}

	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}



// go code to combine multiple flags : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"strings"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var prefix, suffix string
	var echoCmd = &cobra.Command{
		Use:   "echo [message]",
		Short: "Echo the provided message",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			message := args[0]
			fmt.Println(prefix + message + suffix)
		},
	}

	echoCmd.Flags().StringVarP(&prefix, "prefix", "p", "", "prefix for the message")
	echoCmd.Flags().StringVarP(&suffix, "suffix", "s", "", "suffix for the message")
	rootCmd.AddCommand(echoCmd)
	rootCmd.Execute()
}




// code to handle subcommands errors : 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var errorCmd = &cobra.Command{
		Use:   "error",
		Short: "Generate an error",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("an error occurred")
		},
	}

	rootCmd.AddCommand(errorCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}



// code to use nested subcommands : 


package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var nestedCmd = &cobra.Command{
		Use:   "nested",
		Short: "Nested command",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Nested command executed")
		},
	}

	var subCmd = &cobra.Command{
		Use:   "sub",
		Short: "Sub command",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Sub command executed")
		},
	}

	nestedCmd.AddCommand(subCmd)
	rootCmd.AddCommand(nestedCmd)
	rootCmd.Execute()
}




// code to use custom error messages 

package main

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "app"}

func main() {
	var errorCmd = &cobra.Command{
		Use:   "error",
		Short: "Generate an error",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("custom error message")
		},
	}

	rootCmd.AddCommand(errorCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}











// Example 1: Creating a new constraint
//
// This example demonstrates how to create a new constraint using the constraints library.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    fmt.Println(c)
}





// Example 2: Adding a validation rule to a constraint
//
// This example demonstrates how to add a validation rule to a constraint using the constraints library.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("value must be greater than or equal to 10")
        }
        return nil
    })
    fmt.Println(c.Validate(5))
}





// Example 3: Validating a value against a constraint
//
// This example demonstrates how to validate a value against a constraint using the constraints library.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("value must be greater than or equal to 10")
        }
        return nil
    })
    fmt.Println(c.Validate(15))
}





// Example 4: Adding multiple validation rules
//
// This example demonstrates how to add multiple validation rules to a constraint.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("value must be greater than or equal to 10")
        }
        return nil
    })
    c.AddRule(func(value interface{}) error {
        if value.(int) > 20 {
            return fmt.Errorf("value must be less than or equal to 20")
        }
        return nil
    })
    fmt.Println(c.Validate(25))
}





// Example 5: Custom error message
//
// This example demonstrates how to set a custom error message for a validation rule.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("custom error: value must be >= 10")
        }
        return nil
    })
    fmt.Println(c.Validate(5))
}





// Example 6: Chaining constraints
//
// This example demonstrates how to chain multiple constraints together.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c1 := constraints.NewConstraint()
    c1.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("value must be greater than or equal to 10")
        }
        return nil
    })

    c2 := constraints.NewConstraint()
    c2.AddRule(func(value interface{}) error {
        if value.(int) > 20 {
            return fmt.Errorf("value must be less than or equal to 20")
        }
        return nil
    })

    c3 := constraints.NewCompositeConstraint(c1, c2)
    fmt.Println(c3.Validate(15))
}





// Example 7: Using string validation
//
// This example demonstrates how to use string validation in constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if len(value.(string)) < 5 {
            return fmt.Errorf("string length must be at least 5 characters")
        }
        return nil
    })
    fmt.Println(c.Validate("abc"))
}





// Example 8: Numeric range validation
//
// This example demonstrates how to validate a numeric range.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 || value.(int) > 20 {
            return fmt.Errorf("value must be between 10 and 20")
        }
        return nil
    })
    fmt.Println(c.Validate(15))
}





// Example 9: Regular expression validation
//
// This example demonstrates how to use regular expression validation.
//
// Code:
package main

import (
    "fmt"
    "regexp"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        matched, _ := regexp.MatchString(`^[a-z]+$`, value.(string))
        if !matched {
            return fmt.Errorf("value must match regex ^[a-z]+$")
        }
        return nil
    })
    fmt.Println(c.Validate("abc123"))
}





// Example 10: Validating arrays
//
// This example demonstrates how to validate elements within an array.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        for _, v := range value.([]int) {
            if v < 0 {
                return fmt.Errorf("all elements must be non-negative")
            }
        }
        return nil
    })
    fmt.Println(c.Validate([]int{1, 2, -3}))
}





// Example 11: Validating maps
//
// This example demonstrates how to validate values within a map.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        for _, v := range value.(map[string]int) {
            if v < 0 {
                return fmt.Errorf("all map values must be non-negative")
            }
        }
        return nil
    })
    fmt.Println(c.Validate(map[string]int{"a": 1, "b": -2}))
}





// Example 12: Nested constraints
//
// This example demonstrates how to use nested constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c1 := constraints.NewConstraint()
    c1.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    c2 := constraints.NewConstraint()
    c2.AddRule(func(value interface{}) error {
        for _, v := range value.([]int) {
            if err := c1.Validate(v); err != nil {
                return fmt.Errorf("nested validation failed: %v", err)
            }
        }
        return nil
    })

    fmt.Println(c2.Validate([]int{1, -2, 3}))
}





// Example 13: Constraint inheritance
//
// This example demonstrates how to use constraint inheritance.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type CustomConstraint struct {
    *constraints.Constraint
}

func NewCustomConstraint() *CustomConstraint {
    return &CustomConstraint{constraints.NewConstraint()}
}

func main() {
    c := NewCustomConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 10 {
            return fmt.Errorf("value must be >= 10")
        }
        return nil
    })
    fmt.Println(c.Validate(5))
}






// Example 14: Custom constraint types
//
// This example demonstrates how to create custom constraint types.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type PositiveConstraint struct {
    *constraints.Constraint
}

func NewPositiveConstraint() *PositiveConstraint {
    pc := &PositiveConstraint{constraints.NewConstraint()}
    pc.AddRule(func(value interface{}) error {
        if value.(int) <= 0 {
            return fmt.Errorf("value must be positive")
        }
        return nil
    })
    return pc
}

func main() {
    c := NewPositiveConstraint()
    fmt.Println(c.Validate(-1))
}





// Example 15: Combining constraints
//
// This example demonstrates how to combine multiple constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    isNonNegative := constraints.NewConstraint()
    isNonNegative.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    isEven := constraints.NewConstraint()
    isEven.AddRule(func(value interface{}) error {
        if value.(int)%2 != 0 {
            return fmt.Errorf("value must be even")
        }
        return nil
    })

    combined := constraints.NewCompositeConstraint(isNonNegative, isEven)
    fmt.Println(combined.Validate(4))
}





// Example 16: Constraints with custom structs
//
// This example demonstrates how to use constraints with custom structs.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type User struct {
    Age int
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Age < 18 {
            return fmt.Errorf("user must be at least 18 years old")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Age: 15}))
}





// Example 17: Validating nested structs
//
// This example demonstrates how to validate nested structs.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Address struct {
    City string
}

type User struct {
    Name    string
    Address Address
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Address.City == "" {
            return fmt.Errorf("city must not be empty")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Name: "John", Address: Address{City: ""}}))
}





// Example 18: Conditional validation
//
// This example demonstrates how to use conditional validation.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type User struct {
    Age   int
    Email string
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Age >= 18 && user.Email == "" {
            return fmt.Errorf("email is required for users 18 or older")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Age: 20}))
}





// Example 19: Using interface types
//
// This example demonstrates how to use interface types with constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Validatable interface {
    Validate() error
}

type Product struct {
    Price int
}

func (p Product) Validate() error {
    if p.Price <= 0 {
        return fmt.Errorf("price must be positive")
    }
    return nil
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        return value.(Validatable).Validate()
    })
    fmt.Println(c.Validate(Product{Price: -1}))
}





// Example 20: Validating with custom functions
//
// This example demonstrates how to validate using custom functions.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func isValidEmail(email string) bool {
    return len(email) > 5
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if !isValidEmail(value.(string)) {
            return fmt.Errorf("invalid email address")
        }
        return nil
    })
    fmt.Println(c.Validate("a@b.com"))
}





// Example 21: Handling validation errors
//
// This example demonstrates how to handle validation errors.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })
    err := c.Validate(-5)
    if err != nil {
        fmt.Printf("Validation failed: %v\n", err)
    }
}






// Example 22: Asynchronous validation
//
// This example demonstrates how to perform asynchronous validation.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
    "sync"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    var wg sync.WaitGroup
    values := []int{-1, 0, 1}
    for _, v := range values {
        wg.Add(1)
        go func(val int) {
            defer wg.Done()
            fmt.Println(c.Validate(val))
        }(v)
    }
    wg.Wait()
}





// Example 23: Combining synchronous and asynchronous validation
//
// This example demonstrates how to combine synchronous and asynchronous validation.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
    "sync"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    var wg sync.WaitGroup
    values := []int{-1, 0, 1}
    results := make(chan error, len(values))
    for _, v := range values {
        wg.Add(1)
        go func(val int) {
            defer wg.Done()
            results <- c.Validate(val)
        }(v)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for res := range results {
        fmt.Println(res)
    }
}





// Example 23: Combining synchronous and asynchronous validation
//
// This example demonstrates how to combine synchronous and asynchronous validation.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
    "sync"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    var wg sync.WaitGroup
    values := []int{-1, 0, 1}
    results := make(chan error, len(values))
    for _, v := range values {
        wg.Add(1)
        go func(val int) {
            defer wg.Done()
            results <- c.Validate(val)
        }(v)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for res := range results {
        fmt.Println(res)
    }
}





// Example 24: Dynamic constraints
//
// This example demonstrates how to use dynamic constraints based on input.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    minAge := 18
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < minAge {
            return fmt.Errorf("age must be at least %d", minAge)
        }
        return nil
    })
    fmt.Println(c.Validate(17))
}





// Example 25: Validating custom data types
//
// This example demonstrates how to validate custom data types.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Product struct {
    Name  string
    Price float64
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        product := value.(Product)
        if product.Price < 0 {
            return fmt.Errorf("price must be positive")
        }
        return nil
    })
    fmt.Println(c.Validate(Product{Name: "Widget", Price: -9.99}))
}





// Example 26: Using constraints with interfaces
//
// This example demonstrates how to use constraints with interfaces.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Shape interface {
    Area() float64
}

type Circle struct {
    Radius float64
}

func (c Circle) Area() float64 {
    return 3.14 * c.Radius * c.Radius
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(Shape).Area() <= 0 {
            return fmt.Errorf("area must be positive")
        }
        return nil
    })
    fmt.Println(c.Validate(Circle{Radius: -5}))
}





// Example 27: Using dependency injection
//
// This example demonstrates how to use dependency injection with constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Validator struct {
    Constraint *constraints.Constraint
}

func NewValidator(c *constraints.Constraint) *Validator {
    return &Validator{Constraint: c}
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) <= 0 {
            return fmt.Errorf("value must be positive")
        }
        return nil
    })
    validator := NewValidator(c)
    fmt.Println(validator.Constraint.Validate(-1))
}





// Example 28: Reusing constraints
//
// This example demonstrates how to reuse constraints across different contexts.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    nonNegative := constraints.NewConstraint()
    nonNegative.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    fmt.Println(nonNegative.Validate(-1))
    fmt.Println(nonNegative.Validate(10))
}





// Example 29: Using constraints with HTTP handlers
//
// This example demonstrates how to use constraints with HTTP handlers.
//
// Code:
package main

import (
    "fmt"
    "net/http"
    "github.com/go-playground/constraints"
)

func validateUser(c *constraints.Constraint, age int) error {
    return c.Validate(age)
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 18 {
            return fmt.Errorf("user must be at least 18 years old")
        }
        return nil
    })

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        age := 17
        err := validateUser(c, age)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
        } else {
            fmt.Fprintf(w, "Validation passed")
        }
    })
    http.ListenAndServe(":8080", nil)
}





// Example 30: Handling multiple validation errors
//
// This example demonstrates how to handle multiple validation errors.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })
    c.AddRule(func(value interface{}) error {
        if value.(int)%2 != 0 {
            return fmt.Errorf("value must be even")
        }
        return nil
    })
    fmt.Println(c.Validate(-3))
}





// Example 31: Logging validation process
//
// This example demonstrates how to log the validation process.
//
// Code:
package main

import (
    "fmt"
    "log"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        log.Printf("Validating value: %v", value)
        if value.(int) <= 0 {
            return fmt.Errorf("value must be positive")
        }
        return nil
    })
    fmt.Println(c.Validate(-1))
}





// Example 32: Extending constraints library
//
// This example demonstrates how to extend the constraints library with custom logic.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type CustomValidator struct {
    *constraints.Constraint
}

func NewCustomValidator() *CustomValidator {
    return &CustomValidator{constraints.NewConstraint()}
}

func (cv *CustomValidator) AddCustomRule(f func(interface{}) error) {
    cv.AddRule(f)
}

func main() {
    cv := NewCustomValidator()
    cv.AddCustomRule(func(value interface{}) error {
        if value.(int) != 42 {
            return fmt.Errorf("value must be 42")
        }
        return nil
    })
    fmt.Println(cv.Validate(100))
}





// Example 33: Constraints with database records
//
// This example demonstrates how to use constraints to validate database records.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type User struct {
    Name string
    Age  int
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Age < 0 {
            return fmt.Errorf("age must be non-negative")
        }
        return nil
    })

    users := []User{{Name: "Alice", Age: 30}, {Name: "Bob", Age: -5}}
    for _, user := range users {
        err := c.Validate(user)
        if err != nil {
            fmt.Printf("Validation failed for user %s: %v\n", user.Name, err)
        }
    }
}





// Example 34: Dynamic rule based on context
//
// This example demonstrates how to use a dynamic rule based on context.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    maxAge := 65
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) > maxAge {
            return fmt.Errorf("age must be less than or equal to %d", maxAge)
        }
        return nil
    })
    fmt.Println(c.Validate(70))
}





// Example 35: Using constraints in a middleware
//
// This example demonstrates how to use constraints in middleware.
//
// Code:
package main

import (
    "fmt"
    "net/http"
    "github.com/go-playground/constraints"
)

func validateMiddleware(c *constraints.Constraint, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        age := 17
        if err := c.Validate(age); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 18 {
            return fmt.Errorf("user must be at least 18 years old")
        }
        return nil
    })

    http.Handle("/", validateMiddleware(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, "Hello, world!")
    })))
    http.ListenAndServe(":8080", nil)
}





// Example 36: Implementing validation for complex types
//
// This example demonstrates how to implement validation for complex types.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Address struct {
    City string
}

type User struct {
    Name    string
    Address Address
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Name == "" {
            return fmt.Errorf("name must not be empty")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Name: "", Address: Address{City: "New York"}}))
}





// Example 37: Validation with optional fields
//
// This example demonstrates how to perform validation with optional fields.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type User struct {
    Name  string
    Email string
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Name == "" {
            return fmt.Errorf("name must not be empty")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Email: "test@example.com"}))
}





// Example 38: Validation with regular expressions
//
// This example demonstrates how to validate fields using regular expressions.
//
// Code:
package main

import (
    "fmt"
    "regexp"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        email := value.(string)
        if matched, _ := regexp.MatchString(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`, email); !matched {
            return fmt.Errorf("invalid email format")
        }
        return nil
    })
    fmt.Println(c.Validate("invalid-email"))
}





// Example 39: Validating with custom error messages
//
// This example demonstrates how to use custom error messages for validation.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) <= 0 {
            return fmt.Errorf("value must be greater than zero")
        }
        return nil
    })
    fmt.Println(c.Validate(-1))
}





// Example 40: Validating custom collections
//
// This example demonstrates how to validate custom collections.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Collection []int

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        coll := value.(Collection)
        for _, v := range coll {
            if v <= 0 {
                return fmt.Errorf("collection must contain only positive numbers")
            }
        }
        return nil
    })
    fmt.Println(c.Validate(Collection{-1, 2, 3}))
}





// Example 41: Validation with custom tags
//
// This example demonstrates how to perform validation with custom tags.
//
// Code:
package main

import (
    "fmt"
    "reflect"
    "github.com/go-playground/constraints"
)

func main() {
    type User struct {
        Name string `validate:"required"`
    }

    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        v := reflect.ValueOf(value)
        t := v.Type()
        for i := 0; i < t.NumField(); i++ {
            field := t.Field(i)
            tag := field.Tag.Get("validate")
            if tag == "required" && v.Field(i).String() == "" {
                return fmt.Errorf("%s is required", field.Name)
            }
        }
        return nil
    })
    fmt.Println(c.Validate(User{}))
}





// Example 42: Validation with custom struct tags
//
// This example demonstrates how to validate struct fields with custom tags.
//
// Code:
package main

import (
    "fmt"
    "reflect"
    "github.com/go-playground/constraints"
)

type User struct {
    Name string `validate:"required"`
    Age  int    `validate:"min:18"`
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        v := reflect.ValueOf(value)
        t := v.Type()
        for i := 0; i < t.NumField(); i++ {
            field := t.Field(i)
            tag := field.Tag.Get("validate")
            if tag == "required" && v.Field(i).String() == "" {
                return fmt.Errorf("%s is required", field.Name)
            }
            if tag == "min:18" && v.Field(i).Int() < 18 {
                return fmt.Errorf("%s must be at least 18", field.Name)
            }
        }
        return nil
    })
    fmt.Println(c.Validate(User{Name: "John", Age: 15}))
}





// Example 43: Chaining validation rules
//
// This example demonstrates how to chain multiple validation rules.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })
    c.AddRule(func(value interface{}) error {
        if value.(int)%2 != 0 {
            return fmt.Errorf("value must be even")
        }
        return nil
    })
    fmt.Println(c.Validate(-3))
}





// Example 44: Validating map entries
//
// This example demonstrates how to validate map entries.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type UserMap map[string]int

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        userMap := value.(UserMap)
        for k, v := range userMap {
            if v < 0 {
                return fmt.Errorf("%s has an invalid age: %d", k, v)
            }
        }
        return nil
    })
    fmt.Println(c.Validate(UserMap{"Alice": 25, "Bob": -5}))
}





// Example 45: Using multiple constraints
//
// This example demonstrates how to use multiple constraints together.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    nonNegative := constraints.NewConstraint()
    nonNegative.AddRule(func(value interface{}) error {
        if value.(int) < 0 {
            return fmt.Errorf("value must be non-negative")
        }
        return nil
    })

    even := constraints.NewConstraint()
    even.AddRule(func(value interface{}) error {
        if value.(int)%2 != 0 {
            return fmt.Errorf("value must be even")
        }
        return nil
    })

    fmt.Println(nonNegative.Validate(-1))
    fmt.Println(even.Validate(3))
}





// Example 46: Grouping constraints
//
// This example demonstrates how to group constraints.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddGroup(func(g *constraints.Group) {
        g.AddRule(func(value interface{}) error {
            if value.(int) < 0 {
                return fmt.Errorf("value must be non-negative")
            }
            return nil
        })
        g.AddRule(func(value interface{}) error {
            if value.(int)%2 != 0 {
                return fmt.Errorf("value must be even")
            }
            return nil
        })
    })

    fmt.Println(c.Validate(-1))
    fmt.Println(c.Validate(3))
}





// Example 47: Using constraints with structs
//
// This example demonstrates how to use constraints with structs.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type User struct {
    Name string
    Age  int
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Age < 0 {
            return fmt.Errorf("age must be non-negative")
        }
        return nil
    })

    fmt.Println(c.Validate(User{Name: "Alice", Age: -5}))
}





// Example 48: Customizing validation errors
//
// This example demonstrates how to customize validation errors.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) <= 0 {
            return fmt.Errorf("value must be greater than zero")
        }
        return nil
    })

    result := c.Validate(-1)
    if result != nil {
        fmt.Println("Validation failed with error:", result.Error())
    } else {
        fmt.Println("Validation passed")
    }
}





// Example 49: Validating nested structs
//
// This example demonstrates how to validate nested structs.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

type Address struct {
    City string
}

type User struct {
    Name    string
    Address Address
}

func main() {
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        user := value.(User)
        if user.Name == "" {
            return fmt.Errorf("name must not be empty")
        }
        if user.Address.City == "" {
            return fmt.Errorf("address.city must not be empty")
        }
        return nil
    })
    fmt.Println(c.Validate(User{Name: "John", Address: Address{City: ""}}))
}





// Example 50: Validation with custom comparisons
//
// This example demonstrates how to perform validation with custom comparisons.
//
// Code:
package main

import (
    "fmt"
    "github.com/go-playground/constraints"
)

func main() {
    targetValue := 42
    c := constraints.NewConstraint()
    c.AddRule(func(value interface{}) error {
        if value.(int) != targetValue {
            return fmt.Errorf("value must be %d", targetValue)
        }
        return nil
    })
    fmt.Println(c.Validate(50))
}










   
import (
    "math"
)

// Check if in given list of numbers, are any two numbers closer to each other than given threshold.
// >>> HasCloseElements([]float64{1.0, 2.0, 3.0}, 0.5)
// false
// >>> HasCloseElements([]float64{1.0, 2.8, 3.0, 4.0, 5.0, 2.0}, 0.3)
// true


func HasCloseElements(numbers []float64, threshold float64) bool {

    for i := 0; i < len(numbers); i++ {
        for j := i + 1; j < len(numbers); j++ {
            var distance float64 = math.Abs(numbers[i] - numbers[j])
            if distance < threshold {
                return true
            }
        }
    }
    return false
}



   

// Input to this function is a string containing multiple groups of nested parentheses. Your goal is to
// separate those group into separate strings and return the list of those.
// Separate groups are balanced (each open brace is properly closed) and not nested within each other
// Ignore any spaces in the input string.
// >>> SeparateParenGroups('( ) (( )) (( )( ))')
// ['()', '(())', '(()())']


func SeparateParenGroups(paren_string string) []string {

    result := make([]string, 0)
    current_string := make([]rune, 0)
    current_depth := 0

    for _, c := range paren_string {
        if c == '(' {
            current_depth += 1
            current_string = append(current_string, c)
        }else if c== ')'{
            current_depth -= 1
            current_string = append(current_string, c)

            if current_depth == 0{
                result = append(result, string(current_string))
                current_string =  make([]rune, 0)
            }
        }

    }
    return result
}



   
import (
    "math"
)

// Given a positive floating point number, it can be decomposed into
// and integer part (largest integer smaller than given number) and decimals
// (leftover part always smaller than 1).
// 
// Return the decimal part of the number.
// >>> TruncateNumber(3.5)
// 0.5


func TruncateNumber(number float64) float64 {

    return math.Mod(number,1)
}



   

// You're given a list of deposit and withdrawal operations on a bank account that starts with
// zero balance. Your task is to detect if at any point the balance of account fallls below zero, and
// at that point function should return true. Otherwise it should return false.
// >>> BelowZero([1, 2, 3])
// false
// >>> BelowZero([1, 2, -4, 5])
// true


func BelowZero(operations []int) bool {

    balance := 0
    for _, op := range operations {
        balance += op
        if balance < 0 {
            return true
        }
    }
    return false
}



   
import (
    "math"
)

// For a given list of input numbers, calculate Mean Absolute Deviation
// around the mean of this dataset.
// Mean Absolute Deviation is the average absolute difference between each
// element and a centerpoint (mean in this case):
// MAD = average | x - x_mean |
// >>> MeanAbsoluteDeviation([1.0, 2.0, 3.0, 4.0])
// 1.0


func MeanAbsoluteDeviation(numbers []float64) float64 {

    sum := func(numbers []float64) float64 {
        sum := 0.0
        for _, num := range numbers {
            sum += num
        }
        return sum
    }

    mean := sum(numbers) / float64(len(numbers))
    numList := make([]float64, 0)
    for _, x := range numbers {
        numList = append(numList, math.Abs(x-mean))
    }
    return sum(numList) / float64(len(numbers))
}



   

// Insert a number 'delimeter' between every two consecutive elements of input list `numbers'
// >>> Intersperse([], 4)
// []
// >>> Intersperse([1, 2, 3], 4)
// [1, 4, 2, 4, 3]


func Intersperse(numbers []int, delimeter int) []int {

    result := make([]int, 0)
    if len(numbers) == 0 {
        return result
    }
    for i := 0; i < len(numbers)-1; i++ {
        n := numbers[i]
        result = append(result, n)
        result = append(result, delimeter)
    }
    result = append(result, numbers[len(numbers)-1])
    return result
}



   
import (
    "math"
    "strings"
)

// Input to this function is a string represented multiple groups for nested parentheses separated by spaces.
// For each of the group, output the deepest level of nesting of parentheses.
// E.g. (()()) has maximum two levels of nesting while ((())) has three.
// 
// >>> ParseNestedParens('(()()) ((())) () ((())()())')
// [2, 3, 1, 3]


func ParseNestedParens(paren_string string) []int {

    parse_paren_group := func(s string) int {
        depth := 0
        max_depth := 0
        for _, c := range s {
            if c == '(' {
                depth += 1
                max_depth = int(math.Max(float64(depth), float64(max_depth)))
            } else {
                depth -= 1
            }
        }
        return max_depth
    }
    result := make([]int, 0)
    for _, x := range strings.Split(paren_string, " ") {
        result = append(result, parse_paren_group(x))
    }
    return result

}



   
import (
    "strings"
)

// Filter an input list of strings only for ones that contain given substring
// >>> FilterBySubstring([], 'a')
// []
// >>> FilterBySubstring(['abc', 'bacd', 'cde', 'array'], 'a')
// ['abc', 'bacd', 'array']


func FilterBySubstring(stringList []string, substring string) []string {

    result := make([]string, 0)
    for _, x := range stringList {
        if strings.Index(x, substring) != -1 {
            result = append(result, x)
        }
    }
    return result
}



   

// For a given list of integers, return a tuple consisting of a sum and a product of all the integers in a list.
// Empty sum should be equal to 0 and empty product should be equal to 1.
// >>> SumProduct([])
// (0, 1)
// >>> SumProduct([1, 2, 3, 4])
// (10, 24)


func SumProduct(numbers []int) [2]int {

    sum_value := 0
    prod_value := 1

    for _, n := range numbers {
        sum_value += n
        prod_value *= n
    }
    return [2]int{sum_value, prod_value}
}



   
import (
    "math"
)

// From a given list of integers, generate a list of rolling maximum element found until given moment
// in the sequence.
// >>> RollingMax([1, 2, 3, 2, 3, 4, 2])
// [1, 2, 3, 3, 3, 4, 4]


func RollingMax(numbers []int) []int {

    running_max := math.MinInt32
    result := make([]int, 0)

    for _, n := range numbers {
        if running_max == math.MinInt32 {
            running_max = n
        } else {
            running_max = int(math.Max(float64(running_max), float64(n)))
        }
        result = append(result, running_max)
    }

    return result
}



   
import (
    "strings"
)

// Find the shortest palindrome that begins with a supplied string.
// Algorithm idea is simple:
// - Find the longest postfix of supplied string that is a palindrome.
// - Append to the end of the string reverse of a string prefix that comes before the palindromic suffix.
// >>> MakePalindrome('')
// ''
// >>> MakePalindrome('cat')
// 'catac'
// >>> MakePalindrome('cata')
// 'catac'


func MakePalindrome(str string) string {

    if strings.TrimSpace(str) == "" {
        return ""
    }
    beginning_of_suffix := 0
    runes := []rune(str)
    for !IsPalindrome(string(runes[beginning_of_suffix:])) {
        beginning_of_suffix += 1
    }
    result := make([]rune, 0)
    for i := len(str[:beginning_of_suffix]) - 1; i >= 0; i-- {
        result = append(result, runes[i])
    }
    return str + string(result)
}



   
import (
    "fmt"
)

// Input are two strings a and b consisting only of 1s and 0s.
// Perform binary XOR on these inputs and return result also as a string.
// >>> StringXor('010', '110')
// '100'


func StringXor(a string, b string) string {

    s2b := func(bs string) int32 {
        result := int32(0)
        runes := []rune(bs)
        for _, r := range runes {
            result = result << 1
            temp := r - rune('0')
            result += temp
        }
        return result
    }
    ab := s2b(a)
    bb := s2b(b)
    res := ab ^ bb
    sprint := fmt.Sprintf("%b", res)
    for i := 0; i < len(a)-len(sprint); i++ {
        sprint = "0" + sprint
    }
    return sprint
}



   

// Out of list of strings, return the Longest one. Return the first one in case of multiple
// strings of the same length. Return nil in case the input list is empty.
// >>> Longest([])
// nil
// >>> Longest(['a', 'b', 'c'])
// 'a'
// >>> Longest(['a', 'bb', 'ccc'])
// 'ccc'


func Longest(strings []string) interface{}{

    if strings == nil || len(strings) == 0 {
        return nil
    }
    maxlen := 0
    maxi := 0
    for i, s := range strings {
        if maxlen < len(s) {
            maxlen = len(s)
            maxi = i
        }
    }
    return strings[maxi]
}



   

// Return a greatest common divisor of two integers a and b
// >>> GreatestCommonDivisor(3, 5)
// 1
// >>> GreatestCommonDivisor(25, 15)
// 5


func GreatestCommonDivisor(a int,b int) int{

    if b < 2 {
		return b
	}
	var gcd int = 1
	for i := 2; i < b; i++ {
		if a%i == 0 && b%i == 0 {
			gcd = i
		}
	}
	return gcd
}



   

// Return list of all prefixes from shortest to longest of the input string
// >>> AllPrefixes('abc')
// ['a', 'ab', 'abc']


func AllPrefixes(str string) []string{

    prefixes := make([]string, 0, len(str))
	for i := 0; i < len(str); i++ {
		prefixes = append(prefixes, str[:i+1])
	}
	return prefixes
}



   
import (
    "strconv"
)

// Return a string containing space-delimited numbers starting from 0 upto n inclusive.
// >>> StringSequence(0)
// '0'
// >>> StringSequence(5)
// '0 1 2 3 4 5'


func StringSequence(n int) string{

    var seq string
    for i := 0; i <= n; i++ {
        seq += strconv.Itoa(i)
        if i != n {
            seq += " "
        }
    }
    return seq
}



   
import (
    "strings"
)

// Given a string, find out how many distinct characters (regardless of case) does it consist of
// >>> CountDistinctCharacters('xyzXYZ')
// 3
// >>> CountDistinctCharacters('Jerry')
// 4


func CountDistinctCharacters(str string) int{

    lower := strings.ToLower(str)
	count := 0
	set := make(map[rune]bool)
	for _, i := range lower {
		if set[i] == true {
			continue
		} else {
			set[i] = true
			count++
		}
	}
	return count
}




   

// Input to this function is a string representing musical notes in a special ASCII format.
// Your task is to parse this string and return list of integers corresponding to how many beats does each
// not last.
// 
// Here is a legend:
// 'o' - whole note, lasts four beats
// 'o|' - half note, lasts two beats
// '.|' - quater note, lasts one beat
// 
// >>> ParseMusic('o o| .| o| o| .| .| .| .| o o')
// [4, 2, 1, 2, 2, 1, 1, 1, 1, 4, 4]


func ParseMusic(music_string string) []int{

    note_map := map[string]int{"o": 4, "o|": 2, ".|": 1}
	split := strings.Split(music_string, " ")
	result := make([]int, 0)
	for _, x := range split {
		if i, ok := note_map[x]; ok {
			result = append(result, i)
		}
	}
	return result
}




   


// Find how many times a given substring can be found in the original string. Count overlaping cases.
// >>> HowManyTimes('', 'a')
// 0
// >>> HowManyTimes('aaa', 'a')
// 3
// >>> HowManyTimes('aaaa', 'aa')
// 3


func HowManyTimes(str string,substring string) int{

    times := 0
	for i := 0; i < (len(str) - len(substring) + 1); i++ {
		if str[i:i+len(substring)] == substring {
			times += 1
		}
	}
	return times
}




   
import (
    "sort"
    "strings"
)
// Input is a space-delimited string of numberals from 'zero' to 'nine'.
// Valid choices are 'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight' and 'nine'.
// Return the string with numbers sorted from smallest to largest
// >>> SortNumbers('three one five')
// 'one three five'


func SortNumbers(numbers string) string{

    valueMap := map[string]int{
		"zero":  0,
		"one":   1,
		"two":   2,
		"three": 3,
		"four":  4,
		"five":  5,
		"six":   6,
		"seven": 7,
		"eight": 8,
		"nine":  9,
	}
	stringMap := make(map[int]string)
	for s, i := range valueMap {
		stringMap[i] = s
	}
	split := strings.Split(numbers, " ")
	temp := make([]int, 0)
	for _, s := range split {
		if i, ok := valueMap[s]; ok {
			temp = append(temp, i)
		}
	}
	sort.Ints(temp)
	result := make([]string, 0)
	for _, i := range temp {
		result = append(result, stringMap[i])
	}
	return strings.Join(result, " ")
}




   

// From a supplied list of numbers (of length at least two) select and return two that are the closest to each
// other and return them in order (smaller number, larger number).
// >>> FindClosestElements([1.0, 2.0, 3.0, 4.0, 5.0, 2.2])
// (2.0, 2.2)
// >>> FindClosestElements([1.0, 2.0, 3.0, 4.0, 5.0, 2.0])
// (2.0, 2.0)


func FindClosestElements(numbers []float64) [2]float64 {

    distance := math.MaxFloat64
	var closestPair [2]float64
	for idx, elem := range numbers {
		for idx2, elem2 := range numbers {
			if idx != idx2 {
				if distance == math.MinInt64 {
					distance = math.Abs(elem - elem2)
					float64s := []float64{elem, elem2}
					sort.Float64s(float64s)
					closestPair = [2]float64{float64s[0], float64s[1]}
				} else {
					newDistance := math.Abs(elem - elem2)
					if newDistance < distance{
						distance = newDistance
						float64s := []float64{elem, elem2}
						sort.Float64s(float64s)
						closestPair = [2]float64{float64s[0], float64s[1]}
					}
				}
			}
		}
	}
	return closestPair
}




   

// Given list of numbers (of at least two elements), apply a linear transform to that list,
// such that the smallest number will become 0 and the largest will become 1
// >>> RescaleToUnit([1.0, 2.0, 3.0, 4.0, 5.0])
// [0.0, 0.25, 0.5, 0.75, 1.0]


func RescaleToUnit(numbers []float64) []float64 {

    smallest := numbers[0]
	largest := smallest
	for _, n := range numbers {
		if smallest > n {
			smallest = n
		}
		if largest < n {
			largest = n
		}
	}
	if smallest == largest {
		return numbers
	}
	for i, n := range numbers {
		numbers[i] = (n - smallest) / (largest - smallest)
	}
	return numbers
}



   

// Filter given list of any values only for integers
// >>> FilterIntegers(['a', 3.14, 5])
// [5]
// >>> FilterIntegers([1, 2, 3, 'abc', {}, []])
// [1, 2, 3]


func FilterIntegers(values []interface{}) []int {

    result := make([]int, 0)
    for _, val := range values {
        switch i := val.(type) {
        case int:
            result = append(result, i)
        }
    }
    return result
}



   

// Return length of given string
// >>> Strlen('')
// 0
// >>> Strlen('abc')
// 3


func Strlen(str string) int {

    return len(str)
}



   

// For a given number n, find the largest number that divides n evenly, smaller than n
// >>> LargestDivisor(15)
// 5


func LargestDivisor(n int) int {

    for i := n - 1; i > 0; i-- {
		if n % i == 0 {
			return i
		}
	}
	return 0
}



   
import (
    "math"
)
// Return list of prime factors of given integer in the order from smallest to largest.
// Each of the factors should be listed number of times corresponding to how many times it appeares in factorization.
// Input number should be equal to the product of all factors
// >>> Factorize(8)
// [2, 2, 2]
// >>> Factorize(25)
// [5, 5]
// >>> Factorize(70)
// [2, 5, 7]


func Factorize(n int) []int {

    fact := make([]int, 0)
	for i := 2; i <= int(math.Sqrt(float64(n))+1); {
		if n%i == 0 {
			fact = append(fact, i)
			n = n / i
		} else {
			i++
		}
	}
	if n > 1 {
		fact = append(fact, n)
	}
	return fact
}



   

// From a list of integers, remove all elements that occur more than once.
// Keep order of elements left the same as in the input.
// >>> RemoveDuplicates([1, 2, 3, 2, 4])
// [1, 3, 4]


func RemoveDuplicates(numbers []int) []int {

    c := make(map[int] int)
	for _, number := range numbers {
		if i, ok := c[number]; ok {
			c[number] = i + 1
		} else {
			c[number] = 1
		}
	}
	result := make([]int, 0)
	for _, number := range numbers {
		if c[number] <= 1 {
			result = append(result, number)
		}
	}
	return result
}



   
import (
    "strings"
)

// For a given string, flip lowercase characters to uppercase and uppercase to lowercase.
// >>> FlipCase('Hello')
// 'hELLO'


func FlipCase(str string) string {

    result := []rune{}
    for _, c := range str {
        if c >= 'A' && c <= 'Z' {
            result = append(result, 'a' + ((c - 'A' + 26) % 26))
        } else if c >= 'a' && c <= 'z' {
            result = append(result, 'A' + ((c - 'a' + 26) % 26))
        } else {
            result = append(result, c)
        }
    }
    return string(result)
}



   

// Concatenate list of strings into a single string
// >>> Concatenate([])
// ''
// >>> Concatenate(['a', 'b', 'c'])
// 'abc'


func Concatenate(strings []string) string {

    if len(strings) == 0 {
		return ""
	}
	return strings[0] + Concatenate(strings[1:])
}



   

// Filter an input list of strings only for ones that start with a given prefix.
// >>> FilterByPrefix([], 'a')
// []
// >>> FilterByPrefix(['abc', 'bcd', 'cde', 'array'], 'a')
// ['abc', 'array']


func FilterByPrefix(strings []string,prefix string) []string {

    if len(strings) == 0 {
        return []string{}
    }
    res := make([]string, 0, len(strings))
	for _, s := range strings {
		if s[:len(prefix)] == prefix {
			res = append(res, s)
		}
	}
	return res
}




   

// Return only positive numbers in the list.
// >>> GetPositive([-1, 2, -4, 5, 6])
// [2, 5, 6]
// >>> GetPositive([5, 3, -5, 2, -3, 3, 9, 0, 123, 1, -10])
// [5, 3, 2, 3, 9, 123, 1]


func GetPositive(l []int) []int {

    res := make([]int, 0)
    for _, x := range l {
        if x > 0 {
            res = append(res, x)
        }
    }
    return res
}




   

// Return true if a given number is prime, and false otherwise.
// >>> IsPrime(6)
// false
// >>> IsPrime(101)
// true
// >>> IsPrime(11)
// true
// >>> IsPrime(13441)
// true
// >>> IsPrime(61)
// true
// >>> IsPrime(4)
// false
// >>> IsPrime(1)
// false


func IsPrime(n int) bool {

    if n <= 1 {
		return false
	}
	if n == 2 {
		return true
	}
	if n%2 == 0 {
		return false
	}
	for i := 3; i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}




   
import (
    "math"
)

// xs are coefficients of a polynomial.
// FindZero find x such that Poly(x) = 0.
// FindZero returns only only zero point, even if there are many.
// Moreover, FindZero only takes list xs having even number of coefficients
// and largest non zero coefficient as it guarantees
// a solution.
// >>> round(FindZero([1, 2]), 2) # f(x) = 1 + 2x
// -0.5
// >>> round(FindZero([-6, 11, -6, 1]), 2) # (x - 1) * (x - 2) * (x - 3) = -6 + 11x - 6x^2 + x^3
// 1.0


func FindZero(xs []int) float64 {

    begin := -1.0
	end := 1.0
	for Poly(xs, begin)*Poly(xs, end) > 0 {
		begin *= 2
		end *= 2
	}
	for end-begin > 1e-10 {
		center := (begin + end) / 2
		if Poly(xs, center)*Poly(xs, begin) > 0 {
			begin = center
		} else {
			end = center
		}
	}
	return begin
}



   
import (
    "sort"
)
// This function takes a list l and returns a list l' such that
// l' is identical to l in the indicies that are not divisible by three, while its values at the indicies that are divisible by three are equal
// to the values of the corresponding indicies of l, but sorted.
// >>> SortThird([1, 2, 3])
// [1, 2, 3]
// >>> SortThird([5, 6, 3, 4, 8, 9, 2])
// [2, 6, 3, 4, 8, 9, 5]


func SortThird(l []int) []int {

    temp := make([]int, 0)
	for i := 0; i < len(l); i = i + 3 {
		temp = append(temp, l[i])
	}
	sort.Ints(temp)
	j := 0
	for i := 0; i < len(l); i = i + 3 {
		l[i] = temp[j]
		j++
	}
	return l
}



   
import (
    "sort"
)
// Return sorted Unique elements in a list
// >>> Unique([5, 3, 5, 2, 3, 3, 9, 0, 123])
// [0, 2, 3, 5, 9, 123]


func Unique(l []int) []int {

    set := make(map[int]interface{})
	for _, i := range l {
		set[i]=nil
	}
	l = make([]int,0)
	for i, _ := range set {
		l = append(l, i)
	}
	sort.Ints(l)
	return l
}



   

// Return maximum element in the list.
// >>> MaxElement([1, 2, 3])
// 3
// >>> MaxElement([5, 3, -5, 2, -3, 3, 9, 0, 123, 1, -10])
// 123


func MaxElement(l []int) int {

    max := l[0]
	for _, x := range l {
		if x > max {
			max = x
		}
	}
	return max
}



   
import (
	"strconv"
	"strings"
)
// Return the number of times the digit 7 appears in integers less than n which are divisible by 11 or 13.
// >>> FizzBuzz(50)
// 0
// >>> FizzBuzz(78)
// 2
// >>> FizzBuzz(79)
// 3


func FizzBuzz(n int) int {

    ns := make([]int, 0)
	for i := 0; i < n; i++ {
		if i%11 == 0 || i%13 == 0 {
			ns = append(ns, i)
		}
	}
	temp := make([]string, 0)
	for _, i := range ns {
		temp = append(temp, strconv.Itoa(i))
	}
	join := strings.Join(temp, "")
	ans := 0
	for _, c := range join {
		if c == '7' {
			ans++
		}
	}
	return ans
}



   
import (
	"sort"
)
// This function takes a list l and returns a list l' such that
// l' is identical to l in the odd indicies, while its values at the even indicies are equal
// to the values of the even indicies of l, but sorted.
// >>> SortEven([1, 2, 3])
// [1, 2, 3]
// >>> SortEven([5, 6, 3, 4])
// [3, 6, 5, 4]


func SortEven(l []int) []int {

    evens := make([]int, 0)
	for i := 0; i < len(l); i += 2 {
		evens = append(evens, l[i])
	}
	sort.Ints(evens)
	j := 0
	for i := 0; i < len(l); i += 2 {
		l[i] = evens[j]
		j++
	}
	return l
}



   
import (
    "math"
    "strings"
    "time"
)

// returns encoded string by cycling groups of three characters.
// takes as input string encoded with EncodeCyclic function. Returns decoded string.


func DecodeCyclic(s string) string {

    return EncodeCyclic(EncodeCyclic(s))
}



   
import (
	"math"
)
// PrimeFib returns n-th number that is a Fibonacci number and it's also prime.
// >>> PrimeFib(1)
// 2
// >>> PrimeFib(2)
// 3
// >>> PrimeFib(3)
// 5
// >>> PrimeFib(4)
// 13
// >>> PrimeFib(5)
// 89


func PrimeFib(n int) int {

    isPrime := func(p int) bool {
		if p < 2 {
			return false
		}
		for i := 2; i < int(math.Min(math.Sqrt(float64(p))+1, float64(p-1))); i++ {
			if p%i == 0 {
				return false
			}
		}
		return true
	}
	f := []int{0, 1}
	for {
		f = append(f, f[len(f)-1]+f[len(f)-2])
		if isPrime(f[len(f)-1]) {
			n -= 1
		}
		if n == 0 {
			return f[len(f)-1]
		}
	}
}



   

// TriplesSumToZero takes a list of integers as an input.
// it returns true if there are three distinct elements in the list that
// sum to zero, and false otherwise.
// 
// >>> TriplesSumToZero([1, 3, 5, 0])
// false
// >>> TriplesSumToZero([1, 3, -2, 1])
// true
// >>> TriplesSumToZero([1, 2, 3, 7])
// false
// >>> TriplesSumToZero([2, 4, -5, 3, 9, 7])
// true
// >>> TriplesSumToZero([1])
// false


func TriplesSumToZero(l []int) bool {

    for i := 0; i < len(l) - 2; i++ {
		for j := i + 1; j < len(l) - 1; j++ {
			for k := j + 1; k < len(l); k++ {
				if l[i] + l[j] + l[k] == 0 {
					return true
				}
			}
		}
	}
	return false
}



   

// Imagine a road that's a perfectly straight infinitely long line.
// n cars are driving left to right;  simultaneously, a different set of n cars
// are driving right to left.   The two sets of cars start out being very far from
// each other.  All cars move in the same speed.  Two cars are said to collide
// when a car that's moving left to right hits a car that's moving right to left.
// However, the cars are infinitely sturdy and strong; as a result, they continue moving
// in their trajectory as if they did not collide.
// 
// This function outputs the number of such collisions.


func CarRaceCollision(n int) int {

	return n * n
}



   

// Return list with elements incremented by 1.
// >>> IncrList([1, 2, 3])
// [2, 3, 4]
// >>> IncrList([5, 3, 5, 2, 3, 3, 9, 0, 123])
// [6, 4, 6, 3, 4, 4, 10, 1, 124]


func IncrList(l []int) []int {

    n := len(l)
	for i := 0; i < n; i++ {
		l[i]++
	}
	return l
}



   

// PairsSumToZero takes a list of integers as an input.
// it returns true if there are two distinct elements in the list that
// sum to zero, and false otherwise.
// >>> PairsSumToZero([1, 3, 5, 0])
// false
// >>> PairsSumToZero([1, 3, -2, 1])
// false
// >>> PairsSumToZero([1, 2, 3, 7])
// false
// >>> PairsSumToZero([2, 4, -5, 3, 5, 7])
// true
// >>> PairsSumToZero([1])
// false


func PairsSumToZero(l []int) bool {

    seen := map[int]bool{}
	for i := 0; i < len(l); i++ {
		for j := i + 1; j < len(l); j++ {
			if l[i] + l[j] == 0 {
				if _, ok := seen[l[i]]; !ok {
					seen[l[i]] = true
					return true
				}
				if _, ok := seen[l[j]]; !ok {
					seen[l[j]] = true
					return true
				}
			}
		}
	}
	return false
}



   
import (
    "strconv"
)

// Change numerical base of input number x to base.
// return string representation after the conversion.
// base numbers are less than 10.
// >>> ChangeBase(8, 3)
// '22'
// >>> ChangeBase(8, 2)
// '1000'
// >>> ChangeBase(7, 2)
// '111'


func ChangeBase(x int, base int) string {

    if x >= base {
        return ChangeBase(x/base, base) + ChangeBase(x%base, base)
    }
    return strconv.Itoa(x)
}



   

// Given length of a side and high return area for a triangle.
// >>> TriangleArea(5, 3)
// 7.5


func TriangleArea(a float64, h float64) float64 {

    return a * h / 2
}



   

// The Fib4 number sequence is a sequence similar to the Fibbonacci sequnece that's defined as follows:
// Fib4(0) -> 0
// Fib4(1) -> 0
// Fib4(2) -> 2
// Fib4(3) -> 0
// Fib4(n) -> Fib4(n-1) + Fib4(n-2) + Fib4(n-3) + Fib4(n-4).
// Please write a function to efficiently compute the n-th element of the Fib4 number sequence.  Do not use recursion.
// >>> Fib4(5)
// 4
// >>> Fib4(6)
// 8
// >>> Fib4(7)
// 14


func Fib4(n int) int {

    switch n {
	case 0:
		return 0
	case 1:
		return 0
	case 2:
		return 2
	case 3:
		return 0
	default:
		return Fib4(n-1) + Fib4(n-2) + Fib4(n-3) + Fib4(n-4)
	}
}



   
import (
	"sort"
)
// Return Median of elements in the list l.
// >>> Median([3, 1, 2, 4, 5])
// 3
// >>> Median([-10, 4, 6, 1000, 10, 20])
// 15.0


func Median(l []int) float64 {

    sort.Ints(l)
	if len(l)%2==1{
		return float64(l[len(l)/2])
	}else{
		return float64(l[len(l)/2-1]+l[len(l)/2])/2.0
	}
}



   

// Checks if given string is a palindrome
// >>> IsPalindrome('')
// true
// >>> IsPalindrome('aba')
// true
// >>> IsPalindrome('aaaaa')
// true
// >>> IsPalindrome('zbcd')
// false


func IsPalindrome(text string) bool {

    runes := []rune(text)
    result := make([]rune, 0)
    for i := len(runes) - 1; i >= 0; i-- {
        result = append(result, runes[i])
    }
    return text == string(result)
}



   

// Return 2^n modulo p (be aware of numerics).
// >>> Modp(3, 5)
// 3
// >>> Modp(1101, 101)
// 2
// >>> Modp(0, 101)
// 1
// >>> Modp(3, 11)
// 8
// >>> Modp(100, 101)
// 1


func Modp(n int,p int) int {

    ret := 1
    for i:= 0; i < n; i++ {
		ret = (2 * ret) % p
	}
    return ret
}



   

// returns encoded string by shifting every character by 5 in the alphabet.
// takes as input string encoded with encode_shift function. Returns decoded string.


func DecodeShift(s string) string {

    runes := []rune(s)
    newRunes := make([]rune, 0)
    for _, ch := range runes {
        newRunes = append(newRunes, (ch-5-'a')%26+'a')
    }
    return string(runes)
}



   
import (
    "regexp"
)
// RemoveVowels is a function that takes string and returns string without vowels.
// >>> RemoveVowels('')
// ''
// >>> RemoveVowels("abcdef\nghijklm")
// 'bcdf\nghjklm'
// >>> RemoveVowels('abcdef')
// 'bcdf'
// >>> RemoveVowels('aaaaa')
// ''
// >>> RemoveVowels('aaBAA')
// 'B'
// >>> RemoveVowels('zbcd')
// 'zbcd'


func RemoveVowels(text string) string {
    
    var re = regexp.MustCompile("[aeiouAEIOU]")
	text = re.ReplaceAllString(text, "")
	return text
}



   

// Return true if all numbers in the list l are below threshold t.
// >>> BelowThreshold([1, 2, 4, 10], 100)
// true
// >>> BelowThreshold([1, 20, 4, 10], 5)
// false


func BelowThreshold(l []int,t int) bool {

    for _, n := range l {
		if n >= t {
			return false
		}
	}
	return true
}



   

// Add two numbers x and y
// >>> Add(2, 3)
// 5
// >>> Add(5, 7)
// 12


func Add(x int, y int) int {

    return x + y
}



   

// Check if two words have the same characters.
// >>> SameChars('eabcdzzzz', 'dddzzzzzzzddeddabc')
// true
// >>> SameChars('abcd', 'dddddddabc')
// true
// >>> SameChars('dddddddabc', 'abcd')
// true
// >>> SameChars('eabcd', 'dddddddabc')
// false
// >>> SameChars('abcd', 'dddddddabce')
// false
// >>> SameChars('eabcdzzzz', 'dddzzzzzzzddddabc')
// false


func SameChars(s0 string, s1 string) bool {

    set0 := make(map[int32]interface{})
	set1 := make(map[int32]interface{})
	for _, i := range s0 {
		set0[i] = nil
	}
	for _, i := range s1 {
		set1[i] = nil
	}
	for i, _ := range set0 {
		if _,ok:=set1[i];!ok{
			return false
		}
	}
	for i, _ := range set1 {
		if _,ok:=set0[i];!ok{
			return false
		}
	}
	return true
}



   

// Return n-th Fibonacci number.
// >>> Fib(10)
// 55
// >>> Fib(1)
// 1
// >>> Fib(8)
// 21


func Fib(n int) int {

    if n <= 1 {
		return n
	}
	return Fib(n-1) + Fib(n-2)
}



   

// brackets is a string of "<" and ">".
// return true if every opening bracket has a corresponding closing bracket.
// 
// >>> CorrectBracketing("<")
// false
// >>> CorrectBracketing("<>")
// true
// >>> CorrectBracketing("<<><>>")
// true
// >>> CorrectBracketing("><<>")
// false


func CorrectBracketing(brackets string) bool {

    l := len(brackets)
	count := 0
	for index := 0; index < l; index++ {
		if brackets[index] == '<' {
			count++
		} else if brackets[index] == '>' {
			count--
		}
		if count < 0 {
			return false
		}
	}
    if count == 0 {
        return true
    } else {
        return false
    }
}



   

// Return true is list elements are Monotonically increasing or decreasing.
// >>> Monotonic([1, 2, 4, 20])
// true
// >>> Monotonic([1, 20, 4, 10])
// false
// >>> Monotonic([4, 1, 0, -10])
// true


func Monotonic(l []int) bool {

    flag := true
	if len(l) > 1 {
		for i := 0; i < len(l)-1; i++ {
			if l[i] != l[i+1] {
				flag = l[i] > l[i+1]
				break
			}
		}
	} else {
		return false
	}
	for i := 0; i < len(l)-1; i++ {
		if flag != (l[i] >= l[i+1]) {
			return false
		}
	}
	return true
}



   
import (
    "sort"
)
// Return sorted unique Common elements for two lists.
// >>> Common([1, 4, 3, 34, 653, 2, 5], [5, 7, 1, 5, 9, 653, 121])
// [1, 5, 653]
// >>> Common([5, 3, 2, 8], [3, 2])
// [2, 3]


func Common(l1 []int,l2 []int) []int {

    m := make(map[int]bool)
	for _, e1 := range l1 {
		if m[e1] {
			continue
		}
		for _, e2 := range l2 {
			if e1 == e2 {
				m[e1] = true
				break
			}
		}
	}
	res := make([]int, 0, len(m))
	for k, _ := range m {
		res = append(res, k)
	}
	sort.Ints(res)
	return res
}



   

// Return the largest prime factor of n. Assume n > 1 and is not a prime.
// >>> LargestPrimeFactor(13195)
// 29
// >>> LargestPrimeFactor(2048)
// 2


func LargestPrimeFactor(n int) int {

    isPrime := func(n int) bool {
        for i := 2; i < int(math.Pow(float64(n), 0.5)+1); i++ {
            if n%i == 0 {
                return false
            }
        }
        return true
    }

    largest := 1
    for j := 2; j < n + 1; j++ {
		if n % j == 0 && isPrime(j) {
			if j > largest {
				largest = j
			}
		}
	}
    return largest
}



   

// SumToN is a function that sums numbers from 1 to n.
// >>> SumToN(30)
// 465
// >>> SumToN(100)
// 5050
// >>> SumToN(5)
// 15
// >>> SumToN(10)
// 55
// >>> SumToN(1)
// 1


func SumToN(n int) int {

    if n <= 0 {
		return 0
	} else {
		return n + SumToN(n - 1)
	}
}



   
import (
    "strings"
)
// brackets is a string of "(" and ")".
// return true if every opening bracket has a corresponding closing bracket.
// 
// >>> CorrectBracketing("(")
// false
// >>> CorrectBracketing("()")
// true
// >>> CorrectBracketing("(()())")
// true
// >>> CorrectBracketing(")(()")
// false


func CorrectBracketing(brackets string) bool {

    brackets = strings.Replace(brackets, "(", " ( ", -1)
	brackets = strings.Replace(brackets, ")", ") ", -1)
	open := 0
	for _, b := range brackets {
		if b == '(' {
			open++
		} else if b == ')' {
			open--
		}
		if open < 0 {
			return false
		}
	}
	return open == 0
}



   

// xs represent coefficients of a polynomial.
// xs[0] + xs[1] * x + xs[2] * x^2 + ....
// Return Derivative of this polynomial in the same form.
// >>> Derivative([3, 1, 2, 4, 5])
// [1, 4, 12, 20]
// >>> Derivative([1, 2, 3])
// [2, 6]


func Derivative(xs []int) []int {

    l := len(xs)
	y := make([]int, l - 1)
	for i := 0; i < l - 1; i++ {
		y[i] = xs[i + 1] * (i + 1)
	}
	return y
}



   

// The FibFib number sequence is a sequence similar to the Fibbonacci sequnece that's defined as follows:
// Fibfib(0) == 0
// Fibfib(1) == 0
// Fibfib(2) == 1
// Fibfib(n) == Fibfib(n-1) + Fibfib(n-2) + Fibfib(n-3).
// Please write a function to efficiently compute the n-th element of the Fibfib number sequence.
// >>> Fibfib(1)
// 0
// >>> Fibfib(5)
// 4
// >>> Fibfib(8)
// 24


func Fibfib(n int) int {

    if n <= 0 {
		return 0
	}
    switch n {
	case 0:
		return 0
	case 1:
		return 0
	case 2:
		return 1
	default:
		return Fibfib(n-1) + Fibfib(n-2) + Fibfib(n-3)
	}
}



   
import (
    "strings"
)
// Write a function VowelsCount which takes a string representing
// a word as input and returns the number of vowels in the string.
// Vowels in this case are 'a', 'e', 'i', 'o', 'u'. Here, 'y' is also a
// vowel, but only when it is at the end of the given word.
// 
// Example:
// >>> VowelsCount("abcde")
// 2
// >>> VowelsCount("ACEDY")
// 3


func VowelsCount(s string) int {

    s = strings.ToLower(s)
	vowels := map[int32]interface{}{'a': nil, 'e': nil, 'i': nil, 'o': nil, 'u': nil}
	count := 0
	for _, i := range s {
		if _, ok := vowels[i]; ok {
			count++
		}
	}
	if (s[len(s)-1]) == 'y' {
		count++
	}
	return count
}



   
import (
    "strconv"
)
// Circular shift the digits of the integer x, shift the digits right by shift
// and return the result as a string.
// If shift > number of digits, return digits reversed.
// >>> CircularShift(12, 1)
// "21"
// >>> CircularShift(12, 2)
// "12"


func CircularShift(x int, shift int) string {

    s := strconv.Itoa(x)
	if shift > len(s) {
		runes := make([]rune, 0)
		for i := len(s)-1; i >= 0; i-- {
			runes = append(runes, rune(s[i]))
		}
		return string(runes)
	}else{
		return s[len(s)-shift:]+s[:len(s)-shift]
	}
}



   

// Task
// Write a function that takes a string as input and returns the sum of the upper characters only'
// ASCII codes.
// 
// Examples:
// Digitsum("") => 0
// Digitsum("abAB") => 131
// Digitsum("abcCd") => 67
// Digitsum("helloE") => 69
// Digitsum("woArBld") => 131
// Digitsum("aAaaaXa") => 153


func Digitsum(x string) int {

    if len(x) == 0 {
		return 0
	}
	result := 0
	for _, i := range x {
		if 'A' <= i && i <= 'Z' {
			result += int(i)
		}
	}
	return result
}



   
import (
	"strconv"
	"strings"
)
// In this task, you will be given a string that represents a number of apples and oranges
// that are distributed in a basket of fruit this basket contains
// apples, oranges, and mango fruits. Given the string that represents the total number of
// the oranges and apples and an integer that represent the total number of the fruits
// in the basket return the number of the mango fruits in the basket.
// for examble:
// FruitDistribution("5 apples and 6 oranges", 19) ->19 - 5 - 6 = 8
// FruitDistribution("0 apples and 1 oranges",3) -> 3 - 0 - 1 = 2
// FruitDistribution("2 apples and 3 oranges", 100) -> 100 - 2 - 3 = 95
// FruitDistribution("100 apples and 1 oranges",120) -> 120 - 100 - 1 = 19


func FruitDistribution(s string,n int) int {

    split := strings.Split(s, " ")
	for _, i := range split {
		atoi, err := strconv.Atoi(i)
		if err != nil {
			continue
		}
		n = n - atoi
	}
	return n
}



   
import (
    "math"
)
// Given an array representing a branch of a tree that has non-negative integer nodes
// your task is to Pluck one of the nodes and return it.
// The Plucked node should be the node with the smallest even value.
// If multiple nodes with the same smallest even value are found return the node that has smallest index.
// 
// The Plucked node should be returned in a list, [ smalest_value, its index ],
// If there are no even values or the given array is empty, return [].
// 
// Example 1:
// Input: [4,2,3]
// Output: [2, 1]
// Explanation: 2 has the smallest even value, and 2 has the smallest index.
// 
// Example 2:
// Input: [1,2,3]
// Output: [2, 1]
// Explanation: 2 has the smallest even value, and 2 has the smallest index.
// 
// Example 3:
// Input: []
// Output: []
// 
// Example 4:
// Input: [5, 0, 3, 0, 4, 2]
// Output: [0, 1]
// Explanation: 0 is the smallest value, but  there are two zeros,
// so we will choose the first zero, which has the smallest index.
// 
// Constraints:
// * 1 <= nodes.length <= 10000
// * 0 <= node.value


func Pluck(arr []int) []int {

    result := make([]int, 0)
	if len(arr) == 0 {
		return result
	}
	evens := make([]int, 0)
	min := math.MaxInt64
	minIndex := 0
	for i, x := range arr {
		if x%2 == 0 {
			evens = append(evens, x)
			if x < min {
				min = x
				minIndex = i
			}
		}
	}
	if len(evens) == 0 {
		return result
	}
	result = []int{min, minIndex}
	return result
}



   

// You are given a non-empty list of positive integers. Return the greatest integer that is greater than
// zero, and has a frequency greater than or equal to the value of the integer itself.
// The frequency of an integer is the number of times it appears in the list.
// If no such a value exist, return -1.
// Examples:
// Search([4, 1, 2, 2, 3, 1]) == 2
// Search([1, 2, 2, 3, 3, 3, 4, 4, 4]) == 3
// Search([5, 5, 4, 4, 4]) == -1


func Search(lst []int) int {

    countMap := make(map[int]int)
	for _, i := range lst {
		if count, ok := countMap[i]; ok {
			countMap[i] = count + 1
		} else {
			countMap[i] = 1
		}
	}
	max := -1
	for i, count := range countMap {
		if count >= i && count > max {
			max = i
		}
	}
	return max
}



   
import (
    "sort"
)
// Given list of integers, return list in strange order.
// Strange sorting, is when you start with the minimum value,
// then maximum of the remaining integers, then minimum and so on.
// 
// Examples:
// StrangeSortList([1, 2, 3, 4]) == [1, 4, 2, 3]
// StrangeSortList([5, 5, 5, 5]) == [5, 5, 5, 5]
// StrangeSortList([]) == []


func StrangeSortList(lst []int) []int {

    sort.Ints(lst)
	result := make([]int, 0)
	for i := 0; i < len(lst)/2; i++ {
		result = append(result, lst[i])
		result = append(result, lst[len(lst)-i-1])
	}
	if len(lst)%2 != 0 {
		result = append(result, lst[len(lst)/2])
	}
	return result
}



   
import (
    "math"
)
// Given the lengths of the three sides of a triangle. Return the area of
// the triangle rounded to 2 decimal points if the three sides form a valid triangle.
// Otherwise return -1
// Three sides make a valid triangle when the sum of any two sides is greater
// than the third side.
// Example:
// TriangleArea(3, 4, 5) == 6.00
// TriangleArea(1, 2, 10) == -1


func TriangleArea(a float64, b float64, c float64) interface{} {

    if a+b <= c || a+c <= b || b+c <= a {
		return -1
	}
	s := (a + b + c) / 2
	area := math.Pow(s * (s - a) * (s - b) * (s - c), 0.5)
	area = math.Round(area*100)/100
	return area
}



   

// Write a function that returns true if the object q will fly, and false otherwise.
// The object q will fly if it's balanced (it is a palindromic list) and the sum of its elements is less than or equal the maximum possible weight w.
// 
// Example:
// WillItFly([1, 2], 5) ➞ false
// 1+2 is less than the maximum possible weight, but it's unbalanced.
// 
// WillItFly([3, 2, 3], 1) ➞ false
// it's balanced, but 3+2+3 is more than the maximum possible weight.
// 
// WillItFly([3, 2, 3], 9) ➞ true
// 3+2+3 is less than the maximum possible weight, and it's balanced.
// 
// WillItFly([3], 5) ➞ true
// 3 is less than the maximum possible weight, and it's balanced.


func WillItFly(q []int,w int) bool {

    sum := 0
	for i := 0; i < len(q); i++ {
		sum += q[i]
	}
	if sum <= w && isPalindrome(q) {
		return true
	}
	return false
}

func isPalindrome(arr []int) bool {
	for i := 0; i < (len(arr) / 2); i++ {
		if arr[i] != arr[len(arr) - i - 1] {
			return false
		}
	}
	return true
}



   

// Given an array arr of integers, find the minimum number of elements that
// need to be changed to make the array palindromic. A palindromic array is an array that
// is read the same backwards and forwards. In one change, you can change one element to any other element.
// 
// For example:
// SmallestChange([1,2,3,5,4,7,9,6]) == 4
// SmallestChange([1, 2, 3, 4, 3, 2, 2]) == 1
// SmallestChange([1, 2, 3, 2, 1]) == 0


func SmallestChange(arr []int) int {

    count := 0
	for i := 0; i < len(arr) - 1; i++ {
        a := arr[len(arr) - i - 1]
		if arr[i] != a {
			arr[i] = a
            count++
		}
	}
	return count
}



   

// Write a function that accepts two lists of strings and returns the list that has
// total number of chars in the all strings of the list less than the other list.
// 
// if the two lists have the same number of chars, return the first list.
// 
// Examples
// TotalMatch([], []) ➞ []
// TotalMatch(['hi', 'admin'], ['hI', 'Hi']) ➞ ['hI', 'Hi']
// TotalMatch(['hi', 'admin'], ['hi', 'hi', 'admin', 'project']) ➞ ['hi', 'admin']
// TotalMatch(['hi', 'admin'], ['hI', 'hi', 'hi']) ➞ ['hI', 'hi', 'hi']
// TotalMatch(['4'], ['1', '2', '3', '4', '5']) ➞ ['4']


func TotalMatch(lst1 []string,lst2 []string) []string {

    var numchar1 = 0
	var numchar2 = 0
	for _, item := range lst1 {
		numchar1 += len(item)
	}
	for _, item := range lst2 {
		numchar2 += len(item)
	}
	if numchar1 <= numchar2 {
		return lst1
	} else {
		return lst2
	}
}



   

// Write a function that returns true if the given number is the multiplication of 3 prime numbers
// and false otherwise.
// Knowing that (a) is less then 100.
// Example:
// IsMultiplyPrime(30) == true
// 30 = 2 * 3 * 5


func IsMultiplyPrime(a int) bool {

    isPrime := func(n int) bool {
        for i := 2; i < int(math.Pow(float64(n), 0.5)+1); i++ {
            if n%i == 0 {
                return false
            }
        }
        return true
    }
    for i := 2; i < 101; i++ {
		if !isPrime(i) {
			continue
		}
		for j := 2; j < 101; j++ {
			if !isPrime(j) {
				continue
			}
			for k := 2; k < 101; k++ {
				if !isPrime(k) {
					continue
				}
				if i*j*k == a {
					return true
				}
			}
		}
	}
	return false
}



   

// Your task is to write a function that returns true if a number x is a simple
// power of n and false in other cases.
// x is a simple power of n if n**int=x
// For example:
// IsSimplePower(1, 4) => true
// IsSimplePower(2, 2) => true
// IsSimplePower(8, 2) => true
// IsSimplePower(3, 2) => false
// IsSimplePower(3, 1) => false
// IsSimplePower(5, 3) => false


func IsSimplePower(x int,n int) bool {

    if x == 1 {
		return true
	}
	if n==1 {
		return false
	}
	if x % n != 0 {
		return false
	}
	return IsSimplePower(x / n, n)
}



   
import (
    "math"
)
// Write a function that takes an integer a and returns true
// if this ingeger is a cube of some integer number.
// Note: you may assume the input is always valid.
// Examples:
// Iscube(1) ==> true
// Iscube(2) ==> false
// Iscube(-1) ==> true
// Iscube(64) ==> true
// Iscube(0) ==> true
// Iscube(180) ==> false


func Iscube(a int) bool {

    abs := math.Abs(float64(a))
	return int(math.Pow(math.Round(math.Pow(abs, 1.0/3.0)), 3.0)) == int(abs)
}



   

// You have been tasked to write a function that receives
// a hexadecimal number as a string and counts the number of hexadecimal
// digits that are primes (prime number, or a prime, is a natural number
// greater than 1 that is not a product of two smaller natural numbers).
// Hexadecimal digits are 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F.
// Prime numbers are 2, 3, 5, 7, 11, 13, 17,...
// So you have to determine a number of the following digits: 2, 3, 5, 7,
// B (=decimal 11), D (=decimal 13).
// Note: you may assume the input is always correct or empty string,
// and symbols A,B,C,D,E,F are always uppercase.
// Examples:
// For num = "AB" the output should be 1.
// For num = "1077E" the output should be 2.
// For num = "ABED1A33" the output should be 4.
// For num = "123456789ABCDEF0" the output should be 6.
// For num = "2020" the output should be 2.


func HexKey(num string) int {

    primes := map[int32]interface{}{'2': nil, '3': nil, '5': nil, '7': nil, 'B': nil, 'D': nil}
	total := 0
	for _, c := range num {
		if _, ok := primes[c]; ok {
			total++
		}
	}
	return total
}



   
import (
	"fmt"
)
// You will be given a number in decimal form and your task is to convert it to
// binary format. The function should return a string, with each character representing a binary
// number. Each character in the string will be '0' or '1'.
// 
// There will be an extra couple of characters 'db' at the beginning and at the end of the string.
// The extra characters are there to help with the format.
// 
// Examples:
// DecimalToBinary(15)   # returns "db1111db"
// DecimalToBinary(32)   # returns "db100000db"


func DecimalToBinary(decimal int) string {

    return fmt.Sprintf("db%bdb", decimal)
}



   

// You are given a string s.
// Your task is to check if the string is happy or not.
// A string is happy if its length is at least 3 and every 3 consecutive letters are distinct
// For example:
// IsHappy(a) => false
// IsHappy(aa) => false
// IsHappy(abcd) => true
// IsHappy(aabb) => false
// IsHappy(adb) => true
// IsHappy(xyy) => false


func IsHappy(s string) bool {

    if len(s) < 3 {
        return false
    }
    for i := 0; i < len(s)-2; i++ {
        if s[i] == s[i+1] || s[i+1] == s[i+2] || s[i] == s[i+2] {
            return false
        }
    }
    return true
}



   

// It is the last week of the semester and the teacher has to give the grades
// to students. The teacher has been making her own algorithm for grading.
// The only problem is, she has lost the code she used for grading.
// She has given you a list of GPAs for some students and you have to write
// a function that can output a list of letter grades using the following table:
// GPA       |    Letter grade
// 4.0                A+
// > 3.7                A
// > 3.3                A-
// > 3.0                B+
// > 2.7                B
// > 2.3                B-
// > 2.0                C+
// > 1.7                C
// > 1.3                C-
// > 1.0                D+
// > 0.7                D
// > 0.0                D-
// 0.0                E
// 
// 
// Example:
// grade_equation([4.0, 3, 1.7, 2, 3.5]) ==> ["A+", "B", "C-", "C", "A-"]


func NumericalLetterGrade(grades []float64) []string {

letter_grade := make([]string, 0, len(grades))
    for _, gpa := range grades {
        switch {
        case gpa == 4.0:
            letter_grade = append(letter_grade, "A+")
        case gpa > 3.7:
            letter_grade = append(letter_grade, "A")
        case gpa > 3.3:
            letter_grade = append(letter_grade, "A-")
        case gpa > 3.0:
            letter_grade = append(letter_grade, "B+")
        case gpa > 2.7:
            letter_grade = append(letter_grade, "B")
        case gpa > 2.3:
            letter_grade = append(letter_grade, "B-")
        case gpa > 2.0:
            letter_grade = append(letter_grade, "C+")
        case gpa > 1.7:
            letter_grade = append(letter_grade, "C")
        case gpa > 1.3:
            letter_grade = append(letter_grade, "C-")
        case gpa > 1.0:
            letter_grade = append(letter_grade, "D+")
        case gpa > 0.7:
            letter_grade = append(letter_grade, "D")
        case gpa > 0.0:
            letter_grade = append(letter_grade, "D-")
        default:
            letter_grade = append(letter_grade, "E")
        }

    }
    return letter_grade
}



   

// Write a function that takes a string and returns true if the string
// length is a prime number or false otherwise
// Examples
// PrimeLength('Hello') == true
// PrimeLength('abcdcba') == true
// PrimeLength('kittens') == true
// PrimeLength('orange') == false


func PrimeLength(s string) bool {

    l := len(s)
    if l == 0 || l == 1 {
        return false
    }
    for i := 2; i < l; i++ {
        if l%i == 0 {
            return false
        }
    }
    return true
}



   
import (
    "math"
)

// Given a positive integer n, return the count of the numbers of n-digit
// positive integers that start or end with 1.


func StartsOneEnds(n int) int {

    if n == 1 {
        return 1
    }
    return 18 * int(math.Pow(10, float64(n-2)))
}



   
import (
    "fmt"
    "strconv"
)

// Given a positive integer N, return the total sum of its digits in binary.
// 
// Example
// For N = 1000, the sum of digits will be 1 the output should be "1".
// For N = 150, the sum of digits will be 6 the output should be "110".
// For N = 147, the sum of digits will be 12 the output should be "1100".
// 
// Variables:
// @N integer
// Constraints: 0 ≤ N ≤ 10000.
// Output:
// a string of binary number


func Solve(N int) string {

    sum := 0
    for _, c := range strconv.Itoa(N) {
        sum += int(c - '0')
    }
    return fmt.Sprintf("%b", sum)
}



   

// Given a non-empty list of integers lst. Add the even elements that are at odd indices..
// 
// Examples:
// Add([4, 2, 6, 7]) ==> 2


func Add(lst []int) int {

    sum := 0
    for i := 1; i < len(lst); i += 2 {
        if lst[i]%2 == 0 {
            sum += lst[i]
        }
    }
    return sum
}



   
import (
    "sort"
    "strings"
)

// Write a function that takes a string and returns an ordered version of it.
// Ordered version of string, is a string where all words (separated by space)
// are replaced by a new word where all the characters arranged in
// ascending order based on ascii value.
// Note: You should keep the order of words and blank spaces in the sentence.
// 
// For example:
// AntiShuffle('Hi') returns 'Hi'
// AntiShuffle('hello') returns 'ehllo'
// AntiShuffle('Hello World!!!') returns 'Hello !!!Wdlor'


func AntiShuffle(s string) string {

    strs := make([]string, 0)
    for _, i := range strings.Fields(s) {
        word := []rune(i)
        sort.Slice(word, func(i, j int) bool {
            return word[i] < word[j]
        })
        strs = append(strs, string(word))
    }
    return strings.Join(strs, " ")
}



   
import (
    "sort"
)

// You are given a 2 dimensional data, as a nested lists,
// which is similar to matrix, however, unlike matrices,
// each row may contain a different number of columns.
// Given lst, and integer x, find integers x in the list,
// and return list of tuples, [(x1, y1), (x2, y2) ...] such that
// each tuple is a coordinate - (row, columns), starting with 0.
// Sort coordinates initially by rows in ascending order.
// Also, sort coordinates of the row by columns in descending order.
// 
// Examples:
// GetRow([
// [1,2,3,4,5,6],
// [1,2,3,4,1,6],
// [1,2,3,4,5,1]
// ], 1) == [(0, 0), (1, 4), (1, 0), (2, 5), (2, 0)]
// GetRow([], 1) == []
// GetRow([[], [1], [1, 2, 3]], 3) == [(2, 2)]


func GetRow(lst [][]int, x int) [][2]int {

    coords := make([][2]int, 0)
    for i, row := range lst {
        for j, item := range row {
            if item == x {
                coords = append(coords, [2]int{i, j})
            }
        }
    }
    sort.Slice(coords, func(i, j int) bool {
        if coords[i][0] == coords[j][0] {
            return coords[i][1] > coords[j][1]
        }
        return coords[i][0] < coords[j][0]
    })

    return coords
}



   
import (
    "sort"
)

// Given an array of non-negative integers, return a copy of the given array after sorting,
// you will sort the given array in ascending order if the sum( first index value, last index value) is odd,
// or sort it in descending order if the sum( first index value, last index value) is even.
// 
// Note:
// * don't change the given array.
// 
// Examples:
// * SortArray([]) => []
// * SortArray([5]) => [5]
// * SortArray([2, 4, 3, 0, 1, 5]) => [0, 1, 2, 3, 4, 5]
// * SortArray([2, 4, 3, 0, 1, 5, 6]) => [6, 5, 4, 3, 2, 1, 0]


func SortArray(array []int) []int {

    arr := make([]int, len(array))
    copy(arr, array)
    if len(arr) == 0 {
        return arr
    }
    if (arr[0]+arr[len(arr)-1])%2 == 0 {
        sort.Slice(arr, func(i, j int) bool {
            return arr[i] > arr[j]
        })
    } else {
        sort.Slice(arr, func(i, j int) bool {
            return arr[i] < arr[j]
        })
    }
    return arr
}



   
import (
    "strings"
)

// Create a function Encrypt that takes a string as an argument and
// returns a string Encrypted with the alphabet being rotated.
// The alphabet should be rotated in a manner such that the letters
// shift down by two multiplied to two places.
// For example:
// Encrypt('hi') returns 'lm'
// Encrypt('asdfghjkl') returns 'ewhjklnop'
// Encrypt('gf') returns 'kj'
// Encrypt('et') returns 'ix'


func Encrypt(s string) string {

    d := "abcdefghijklmnopqrstuvwxyz"
    out := make([]rune, 0, len(s))
    for _, c := range s {
        pos := strings.IndexRune(d, c)
        if pos != -1 {
            out = append(out, []rune(d)[(pos+2*2)%26])
        } else {
            out = append(out, c)
        }
    }
    return string(out)
}



   
import (
    "math"
    "sort"
)

// You are given a list of integers.
// Write a function NextSmallest() that returns the 2nd smallest element of the list.
// Return nil if there is no such element.
// 
// NextSmallest([1, 2, 3, 4, 5]) == 2
// NextSmallest([5, 1, 4, 3, 2]) == 2
// NextSmallest([]) == nil
// NextSmallest([1, 1]) == nil


func NextSmallest(lst []int) interface{} {

    set := make(map[int]struct{})
    for _, i := range lst {
        set[i] = struct{}{}
    }
    vals := make([]int, 0, len(set))
    for k := range set {
        vals = append(vals, k)
    }
    sort.Slice(vals, func(i, j int) bool {
        return vals[i] < vals[j]
    })
    if len(vals) < 2 {
        return nil
    }
    return vals[1]
}



   
import (
    "regexp"
)

// You'll be given a string of words, and your task is to count the number
// of boredoms. A boredom is a sentence that starts with the word "I".
// Sentences are delimited by '.', '?' or '!'.
// 
// For example:
// >>> IsBored("Hello world")
// 0
// >>> IsBored("The sky is blue. The sun is shining. I love this weather")
// 1


func IsBored(S string) int {

    r, _ := regexp.Compile(`[.?!]\s*`)
    sentences := r.Split(S, -1)
    sum := 0
    for _, s := range sentences {
        if len(s) >= 2 && s[:2] == "I " {
            sum++
        }
    }
    return sum
}



   

// Create a function that takes 3 numbers.
// Returns true if one of the numbers is equal to the sum of the other two, and all numbers are integers.
// Returns false in any other cases.
// 
// Examples
// AnyInt(5, 2, 7) ➞ true
// 
// AnyInt(3, 2, 2) ➞ false
// 
// AnyInt(3, -2, 1) ➞ true
// 
// AnyInt(3.6, -2.2, 2) ➞ false


func AnyInt(x, y, z interface{}) bool {

    xx, ok := x.(int)
    if !ok {
        return false
    }
    yy, ok := y.(int)
    if !ok {
        return false
    }
    zz, ok := z.(int)
    if !ok {
        return false
    }

    if (xx+yy == zz) || (xx+zz == yy) || (yy+zz == xx) {
        return true
    }
    return false
}



   
import (
    "strings"
)

// Write a function that takes a message, and Encodes in such a
// way that it swaps case of all letters, replaces all vowels in
// the message with the letter that appears 2 places ahead of that
// vowel in the english alphabet.
// Assume only letters.
// 
// Examples:
// >>> Encode('test')
// 'TGST'
// >>> Encode('This is a message')
// 'tHKS KS C MGSSCGG'


func Encode(message string) string {

    vowels := "aeiouAEIOU"
    vowels_replace := make(map[rune]rune)
    for _, c := range vowels {
        vowels_replace[c] = c + 2
    }
    result := make([]rune, 0, len(message))
    for _, c := range message {
        if 'a' <= c && c <= 'z' {
            c += 'A' - 'a'
        } else if 'A' <= c && c <= 'Z' {
            c += 'a' - 'A'
        }
        if strings.ContainsRune(vowels, c) {
            result = append(result, vowels_replace[c])
        } else {
            result = append(result, c)
        }
    }
    return string(result)
}



   
import (
    "math"
    "strconv"
)

// You are given a list of integers.
// You need to find the largest prime value and return the sum of its digits.
// 
// Examples:
// For lst = [0,3,2,1,3,5,7,4,5,5,5,2,181,32,4,32,3,2,32,324,4,3] the output should be 10
// For lst = [1,0,1,8,2,4597,2,1,3,40,1,2,1,2,4,2,5,1] the output should be 25
// For lst = [1,3,1,32,5107,34,83278,109,163,23,2323,32,30,1,9,3] the output should be 13
// For lst = [0,724,32,71,99,32,6,0,5,91,83,0,5,6] the output should be 11
// For lst = [0,81,12,3,1,21] the output should be 3
// For lst = [0,8,1,2,1,7] the output should be 7


func Skjkasdkd(lst []int) int {

    isPrime := func(n int) bool {
        for i := 2; i < int(math.Pow(float64(n), 0.5)+1); i++ {
            if n%i == 0 {
                return false
            }
        }
        return true
    }
    maxx := 0
    i := 0
    for i < len(lst) {
        if lst[i] > maxx && isPrime(lst[i]) {
            maxx = lst[i]
        }
        i++
    }
    sum := 0
    for _, d := range strconv.Itoa(maxx) {
        sum += int(d - '0')
    }
    return sum
}



   
import (
    "strings"
)

// Given a dictionary, return true if all keys are strings in lower
// case or all keys are strings in upper case, else return false.
// The function should return false is the given dictionary is empty.
// Examples:
// CheckDictCase({"a":"apple", "b":"banana"}) should return true.
// CheckDictCase({"a":"apple", "A":"banana", "B":"banana"}) should return false.
// CheckDictCase({"a":"apple", 8:"banana", "a":"apple"}) should return false.
// CheckDictCase({"Name":"John", "Age":"36", "City":"Houston"}) should return false.
// CheckDictCase({"STATE":"NC", "ZIP":"12345" }) should return true.


func CheckDictCase(dict map[interface{}]interface{}) bool {

    if len(dict) == 0 {
        return false
    }
    state := "start"
    key := ""
    ok := false
    for k := range dict {
        if key, ok = k.(string); !ok {
            state = "mixed"
            break
        }
        if state == "start" {
            if key == strings.ToUpper(key) {
                state = "upper"
            } else if key == strings.ToLower(key) {
                state = "lower"
            } else {
                break
            }
        } else if (state == "upper" && key != strings.ToUpper(key)) || (state == "lower" && key != strings.ToLower(key)) {
            state = "mixed"
            break
        } else {
            break
        }
    }
    return state == "upper" || state == "lower"
}



   

// Implement a function that takes an non-negative integer and returns an array of the first n
// integers that are prime numbers and less than n.
// for example:
// CountUpTo(5) => [2,3]
// CountUpTo(11) => [2,3,5,7]
// CountUpTo(0) => []
// CountUpTo(20) => [2,3,5,7,11,13,17,19]
// CountUpTo(1) => []
// CountUpTo(18) => [2,3,5,7,11,13,17]


func CountUpTo(n int) []int {

    primes := make([]int, 0)
    for i := 2; i < n; i++ {
        is_prime := true
        for j := 2; j < i; j++ {
            if i%j == 0 {
                is_prime = false
                break
            }
        }
        if is_prime {
            primes = append(primes, i)
        }
    }
    return primes
}



   
import (
    "math"
)

// Complete the function that takes two integers and returns
// the product of their unit digits.
// Assume the input is always valid.
// Examples:
// Multiply(148, 412) should return 16.
// Multiply(19, 28) should return 72.
// Multiply(2020, 1851) should return 0.
// Multiply(14,-15) should return 20.


func Multiply(a, b int) int {

    return int(math.Abs(float64(a%10)) * math.Abs(float64(b%10)))
}



   
import (
    "strings"
)

// Given a string s, count the number of uppercase vowels in even indices.
// 
// For example:
// CountUpper('aBCdEf') returns 1
// CountUpper('abcdefg') returns 0
// CountUpper('dBBE') returns 0


func CountUpper(s string) int {

    count := 0
    runes := []rune(s)
    for i := 0; i < len(runes); i += 2 {
        if strings.ContainsRune("AEIOU", runes[i]) {
            count += 1
        }
    }
    return count
}



   
import (
    "math"
    "strconv"
    "strings"
)

// Create a function that takes a value (string) representing a number
// and returns the closest integer to it. If the number is equidistant
// from two integers, round it away from zero.
// 
// Examples
// >>> ClosestInteger("10")
// 10
// >>> ClosestInteger("15.3")
// 15
// 
// Note:
// Rounding away from zero means that if the given number is equidistant
// from two integers, the one you should return is the one that is the
// farthest from zero. For example ClosestInteger("14.5") should
// return 15 and ClosestInteger("-14.5") should return -15.


func ClosestInteger(value string) int {

    if strings.Count(value, ".") == 1 {
        // remove trailing zeros
        for value[len(value)-1] == '0' {
            value = value[:len(value)-1]
        }
    }
    var res float64
    num, _ := strconv.ParseFloat(value, 64)
    if len(value) >= 2 && value[len(value)-2:] == ".5" {
        if num > 0 {
            res = math.Ceil(num)
        } else {
            res = math.Floor(num)
        }
    } else if len(value) > 0 {
        res = math.Round(num)
    } else {
        res = 0
    }

    return int(res)
}



   

// Given a positive integer n, you have to make a pile of n levels of stones.
// The first level has n stones.
// The number of stones in the next level is:
// - the next odd number if n is odd.
// - the next even number if n is even.
// Return the number of stones in each level in a list, where element at index
// i represents the number of stones in the level (i+1).
// 
// Examples:
// >>> MakeAPile(3)
// [3, 5, 7]


func MakeAPile(n int) []int {

    result := make([]int, 0, n)
    for i := 0; i < n; i++ {
        result = append(result, n+2*i)
    }
    return result
}



   
import (
    "strings"
)

// You will be given a string of words separated by commas or spaces. Your task is
// to split the string into words and return an array of the words.
// 
// For example:
// WordsString("Hi, my name is John") == ["Hi", "my", "name", "is", "John"]
// WordsString("One, two, three, four, five, six") == ["One", "two", "three", "four", "five", "six"]


func WordsString(s string) []string {

    s_list := make([]rune, 0)

    for _, c := range s {
        if c == ',' {
            s_list = append(s_list, ' ')
        } else {
            s_list = append(s_list, c)
        }
    }
    return strings.Fields(string(s_list))
}



   

// This function takes two positive numbers x and y and returns the
// biggest even integer number that is in the range [x, y] inclusive. If
// there's no such number, then the function should return -1.
// 
// For example:
// ChooseNum(12, 15) = 14
// ChooseNum(13, 12) = -1


func ChooseNum(x, y int) int {

    if x > y {
        return -1
    }
    if y % 2 == 0 {
        return y
    }
    if x == y {
        return -1
    }
    return y - 1
}



   
import (
    "fmt"
    "math"
)

// You are given two positive integers n and m, and your task is to compute the
// average of the integers from n through m (including n and m).
// Round the answer to the nearest integer and convert that to binary.
// If n is greater than m, return -1.
// Example:
// RoundedAvg(1, 5) => "0b11"
// RoundedAvg(7, 5) => -1
// RoundedAvg(10, 20) => "0b1111"
// RoundedAvg(20, 33) => "0b11010"


func RoundedAvg(n, m int) interface{} {

    if m < n {
        return -1
    }
    summation := 0
    for i := n;i < m+1;i++{
        summation += i
    }
    return fmt.Sprintf("0b%b", int(math.Round(float64(summation)/float64(m - n + 1))))
}



   
import (
    "sort"
    "strconv"
)

// Given a list of positive integers x. return a sorted list of all
// elements that hasn't any even digit.
// 
// Note: Returned list should be sorted in increasing order.
// 
// For example:
// >>> UniqueDigits([15, 33, 1422, 1])
// [1, 15, 33]
// >>> UniqueDigits([152, 323, 1422, 10])
// []


func UniqueDigits(x []int) []int {

    odd_digit_elements := make([]int, 0)
    OUTER:
    for _, i := range x {
        for _, c := range strconv.Itoa(i) {
            if (c - '0') % 2 == 0 {
                continue OUTER
            }
        }
            odd_digit_elements = append(odd_digit_elements, i)
    }
    sort.Slice(odd_digit_elements, func(i, j int) bool {
        return odd_digit_elements[i] < odd_digit_elements[j]
    })
    return odd_digit_elements
}



   
import (
    "sort"
)

// Given an array of integers, sort the integers that are between 1 and 9 inclusive,
// reverse the resulting array, and then replace each digit by its corresponding name from
// "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine".
// 
// For example:
// arr = [2, 1, 1, 4, 5, 8, 2, 3]
// -> sort arr -> [1, 1, 2, 2, 3, 4, 5, 8]
// -> reverse arr -> [8, 5, 4, 3, 2, 2, 1, 1]
// return ["Eight", "Five", "Four", "Three", "Two", "Two", "One", "One"]
// 
// If the array is empty, return an empty array:
// arr = []
// return []
// 
// If the array has any strange number ignore it:
// arr = [1, -1 , 55]
// -> sort arr -> [-1, 1, 55]
// -> reverse arr -> [55, 1, -1]
// return = ['One']


func ByLength(arr []int)[]string {

    dic := map[int]string{
        1: "One",
        2: "Two",
        3: "Three",
        4: "Four",
        5: "Five",
        6: "Six",
        7: "Seven",
        8: "Eight",
        9: "Nine",
    }
    sort.Slice(arr, func(i, j int) bool {
        return arr[i] > arr[j]
    })
    new_arr := make([]string, 0)
    for _, item := range arr {
        if v, ok := dic[item]; ok {
            new_arr = append(new_arr, v)
        }
    }
    return new_arr
}



   


// Implement the Function F that takes n as a parameter,
// and returns a list oF size n, such that the value oF the element at index i is the Factorial oF i iF i is even
// or the sum oF numbers From 1 to i otherwise.
// i starts From 1.
// the Factorial oF i is the multiplication oF the numbers From 1 to i (1 * 2 * ... * i).
// Example:
// F(5) == [1, 2, 6, 24, 15]


func F(n int) []int {

    ret := make([]int, 0, 5)
    for i:=1;i<n+1;i++{
        if i%2 == 0 {
            x := 1
            for j:=1;j<i+1;j++{
                x*=j
            }
            ret = append(ret, x)
        }else {
            x := 0
            for j:=1;j<i+1;j++{
                x+=j
            }
            ret = append(ret, x)
        }
    }
    return ret
}



   
import (
    "strconv"
)

// Given a positive integer n, return a tuple that has the number of even and odd
// integer palindromes that fall within the range(1, n), inclusive.
// 
// Example 1:
// 
// Input: 3
// Output: (1, 2)
// Explanation:
// Integer palindrome are 1, 2, 3. one of them is even, and two of them are odd.
// 
// Example 2:
// 
// Input: 12
// Output: (4, 6)
// Explanation:
// Integer palindrome are 1, 2, 3, 4, 5, 6, 7, 8, 9, 11. four of them are even, and 6 of them are odd.
// 
// Note:
// 1. 1 <= n <= 10^3
// 2. returned tuple has the number of even and odd integer palindromes respectively.


func EvenOddPalindrome(n int) [2]int {

    is_palindrome := func (n int) bool {
        s := strconv.Itoa(n)
        for i := 0;i < len(s)>>1;i++ {
            if s[i] != s[len(s)-i-1] {
                return false
            }
        }
        return true
    }

    even_palindrome_count := 0
    odd_palindrome_count := 0

    for i :=1;i<n+1;i++ {
        if i%2 == 1 && is_palindrome(i){
                odd_palindrome_count ++
        } else if i%2 == 0 && is_palindrome(i) {
            even_palindrome_count ++
        }
    }
    return [2]int{even_palindrome_count, odd_palindrome_count}
}



   
import (
    "math"
    "strconv"
)

// Write a function CountNums which takes an array of integers and returns
// the number of elements which has a sum of digits > 0.
// If a number is negative, then its first signed digit will be negative:
// e.g. -123 has signed digits -1, 2, and 3.
// >>> CountNums([]) == 0
// >>> CountNums([-1, 11, -11]) == 1
// >>> CountNums([1, 1, 2]) == 3


func CountNums(arr []int) int {

    digits_sum:= func (n int) int {
        neg := 1
        if n < 0 {
             n, neg = -1 * n, -1 
        }
        r := make([]int,0)
        for _, c := range strconv.Itoa(n) {
            r = append(r, int(c-'0'))
        }
        r[0] *= neg
        sum := 0
        for _, i := range r {
            sum += i
        }
        return sum
    }
    count := 0
    for _, i := range arr {
        x := digits_sum(i)
        if x > 0 {
            count++
        }
    }
    return count
}



   
import (
    "math"
    "sort"
)

// We have an array 'arr' of N integers arr[1], arr[2], ..., arr[N].The
// numbers in the array will be randomly ordered. Your task is to determine if
// it is possible to get an array sorted in non-decreasing order by performing
// the following operation on the given array:
// You are allowed to perform right shift operation any number of times.
// 
// One right shift operation means shifting all elements of the array by one
// position in the right direction. The last element of the array will be moved to
// the starting position in the array i.e. 0th index.
// 
// If it is possible to obtain the sorted array by performing the above operation
// then return true else return false.
// If the given array is empty then return true.
// 
// Note: The given list is guaranteed to have unique elements.
// 
// For Example:
// 
// MoveOneBall([3, 4, 5, 1, 2])==>true
// Explanation: By performin 2 right shift operations, non-decreasing order can
// be achieved for the given array.
// MoveOneBall([3, 5, 4, 1, 2])==>false
// Explanation:It is not possible to get non-decreasing order for the given
// array by performing any number of right shift operations.


func MoveOneBall(arr []int) bool {

    if len(arr)==0 {
      return true
    }
    sorted_array := make([]int, len(arr))
    copy(sorted_array, arr)
    sort.Slice(sorted_array, func(i, j int) bool {
        return sorted_array[i] < sorted_array[j]
    })    
    min_value := math.MaxInt
    min_index := -1
    for i, x := range arr {
        if i < min_value {
            min_index, min_value = i, x
        }
    }
    my_arr := make([]int, len(arr[min_index:]))
    copy(my_arr, arr[min_index:])
    my_arr = append(my_arr, arr[0:min_index]...)
    for i :=0;i<len(arr);i++ {
      if my_arr[i]!=sorted_array[i]{
        return false
      }
    }
    return true
}



   

// In this problem, you will implement a function that takes two lists of numbers,
// and determines whether it is possible to perform an Exchange of elements
// between them to make lst1 a list of only even numbers.
// There is no limit on the number of Exchanged elements between lst1 and lst2.
// If it is possible to Exchange elements between the lst1 and lst2 to make
// all the elements of lst1 to be even, return "YES".
// Otherwise, return "NO".
// For example:
// Exchange([1, 2, 3, 4], [1, 2, 3, 4]) => "YES"
// Exchange([1, 2, 3, 4], [1, 5, 3, 4]) => "NO"
// It is assumed that the input lists will be non-empty.


func Exchange(lst1, lst2 []int) string {

    odd := 0
    even := 0
    for _, i := range lst1 {
        if i%2 == 1 {
            odd++
        }
    }
    for _, i := range lst2 {
        if i%2 == 0 {
            even++
        }
    }
    if even >= odd {
        return "YES"
    }
    return "NO"
}
            



   
import (
    "strings"
)

// Given a string representing a space separated lowercase letters, return a dictionary
// of the letter with the most repetition and containing the corresponding count.
// If several letters have the same occurrence, return all of them.
// 
// Example:
// Histogram('a b c') == {'a': 1, 'b': 1, 'c': 1}
// Histogram('a b b a') == {'a': 2, 'b': 2}
// Histogram('a b c a b') == {'a': 2, 'b': 2}
// Histogram('b b b b a') == {'b': 4}
// Histogram('') == {}


func Histogram(test string) map[rune]int {

    dict1 := make(map[rune]int)
    list1 := strings.Fields(test)
    t := 0
    count := func(lst []string, v string) int {
        cnt := 0
        for _, i := range lst {
            if i == v {
                cnt++
            }
        }
        return cnt
    }
    for _, i := range list1 {
        if c := count(list1, i); c>t && i!="" {
            t=c
        }
    }
    if t>0 {
        for _, i := range list1 {
            if count(list1, i)==t {
                dict1[[]rune(i)[0]]=t
            }
        }
    }
    return dict1
}



   
import (
    "strings"
)

// Task
// We are given two strings s and c, you have to deleted all the characters in s that are equal to any character in c
// then check if the result string is palindrome.
// A string is called palindrome if it reads the same backward as forward.
// You should return a tuple containing the result string and true/false for the check.
// Example
// For s = "abcde", c = "ae", the result should be ('bcd',false)
// For s = "abcdef", c = "b"  the result should be ('acdef',false)
// For s = "abcdedcba", c = "ab", the result should be ('cdedc',true)


func ReverseDelete(s,c string) [2]interface{} {

    rs := make([]rune, 0)
    for _, r := range s {
        if !strings.ContainsRune(c, r) {
            rs = append(rs, r)
        }
    }
    t := true
    for i := 0;i < len(rs)>>1;i++ {
        if rs[i] != rs[len(rs)-i-1] {
            t=false
            break
        }
    }
    return [2]interface{}{string(rs), t}
}



   
import (
    "fmt"
)

// Given a list of strings, where each string consists of only digits, return a list.
// Each element i of the output should be "the number of odd elements in the
// string i of the input." where all the i's should be replaced by the number
// of odd digits in the i'th string of the input.
// 
// >>> OddCount(['1234567'])
// ["the number of odd elements 4n the str4ng 4 of the 4nput."]
// >>> OddCount(['3',"11111111"])
// ["the number of odd elements 1n the str1ng 1 of the 1nput.",
// "the number of odd elements 8n the str8ng 8 of the 8nput."]


func OddCount(lst []string) []string {

    res := make([]string, 0, len(lst))
    for _, arr := range lst {
        n := 0
        for _, d := range arr {
            if (d - '0') % 2 == 1 {
                n++
            }
        }
        res = append(res, fmt.Sprintf("the number of odd elements %dn the str%dng %d of the %dnput.", n,n,n,n))
    }
    return res
}



   
import (
    "math"
)

// Given an array of integers nums, find the minimum sum of any non-empty sub-array
// of nums.
// Example
// Minsubarraysum([2, 3, 4, 1, 2, 4]) == 1
// Minsubarraysum([-1, -2, -3]) == -6


func Minsubarraysum(nums []int) int {

    max_sum := 0
    s := 0
    for _, num := range nums {
        s += -num
        if s < 0 {
            s = 0
        }
        if s > max_sum {
            max_sum = s
        }
    }
    if max_sum == 0 {
        max_sum = math.MinInt
        for _, i := range nums {
            if -i > max_sum {
                max_sum = -i
            }
        }
    }
    return -max_sum
}



   
import (
    "math"
)

// You are given a rectangular grid of wells. Each row represents a single well,
// and each 1 in a row represents a single unit of water.
// Each well has a corresponding bucket that can be used to extract water from it,
// and all buckets have the same capacity.
// Your task is to use the buckets to empty the wells.
// Output the number of times you need to lower the buckets.
// 
// Example 1:
// Input:
// grid : [[0,0,1,0], [0,1,0,0], [1,1,1,1]]
// bucket_capacity : 1
// Output: 6
// 
// Example 2:
// Input:
// grid : [[0,0,1,1], [0,0,0,0], [1,1,1,1], [0,1,1,1]]
// bucket_capacity : 2
// Output: 5
// 
// Example 3:
// Input:
// grid : [[0,0,0], [0,0,0]]
// bucket_capacity : 5
// Output: 0
// 
// Constraints:
// * all wells have the same length
// * 1 <= grid.length <= 10^2
// * 1 <= grid[:,1].length <= 10^2
// * grid[i][j] -> 0 | 1
// * 1 <= capacity <= 10


func MaxFill(grid [][]int, capacity int) int {

    result := 0
    for _, arr := range grid {
        sum := 0
        for _, i := range arr {
            sum += i
        }
        result += int(math.Ceil(float64(sum) / float64(capacity)))
    }
    return result
}



   
import (
    "fmt"
    "sort"
)

// In this Kata, you have to sort an array of non-negative integers according to
// number of ones in their binary representation in ascending order.
// For similar number of ones, sort based on decimal value.
// 
// It must be implemented like this:
// >>> SortArray([1, 5, 2, 3, 4]) == [1, 2, 3, 4, 5]
// >>> SortArray([-2, -3, -4, -5, -6]) == [-6, -5, -4, -3, -2]
// >>> SortArray([1, 0, 2, 3, 4]) [0, 1, 2, 3, 4]


func SortArray(arr []int) []int {

    sort.Slice(arr, func(i, j int) bool {
        return arr[i] < arr[j]
    })
    sort.Slice(arr, func(i, j int) bool {
        key := func(x int) int {
            b := fmt.Sprintf("%b", x)
            cnt := 0
            for _, r := range b {
                if r == '1' {
                    cnt++
                }
            }
            return cnt
        }
        return key(arr[i]) < key(arr[j])
    })
    return arr
}



   
import (
    "bytes"
    "strings"
)

// Given a string s and a natural number n, you have been tasked to implement
// a function that returns a list of all words from string s that contain exactly
// n consonants, in order these words appear in the string s.
// If the string s is empty then the function should return an empty list.
// Note: you may assume the input string contains only letters and spaces.
// Examples:
// SelectWords("Mary had a little lamb", 4) ==> ["little"]
// SelectWords("Mary had a little lamb", 3) ==> ["Mary", "lamb"]
// SelectWords("simple white space", 2) ==> []
// SelectWords("Hello world", 4) ==> ["world"]
// SelectWords("Uncle sam", 3) ==> ["Uncle"]


func SelectWords(s string, n int) []string {

    result := make([]string, 0)
    for _, word := range strings.Fields(s) {
        n_consonants := 0
        lower := strings.ToLower(word)
        for i := 0;i < len(word); i++ {
            if !bytes.Contains([]byte("aeiou"), []byte{lower[i]}) {
                n_consonants++
            }
        }
        if n_consonants == n{
            result = append(result, word)
        }
    }
    return result
}



   
import (
    "bytes"
)

// You are given a word. Your task is to find the closest vowel that stands between
// two consonants from the right side of the word (case sensitive).
// 
// Vowels in the beginning and ending doesn't count. Return empty string if you didn't
// find any vowel met the above condition.
// 
// You may assume that the given string contains English letter only.
// 
// Example:
// GetClosestVowel("yogurt") ==> "u"
// GetClosestVowel("FULL") ==> "U"
// GetClosestVowel("quick") ==> ""
// GetClosestVowel("ab") ==> ""


func GetClosestVowel(word string) string {

    if len(word) < 3 {
        return ""
    }

    vowels := []byte("aeiouAEOUI")
    for i := len(word)-2; i > 0; i-- {
        if bytes.Contains(vowels, []byte{word[i]}) {
            if !bytes.Contains(vowels, []byte{word[i+1]}) && !bytes.Contains(vowels, []byte{word[i-1]}) {
                return string(word[i])
            }
        }
    }
    return ""
}



   

// You are given a list of two strings, both strings consist of open
// parentheses '(' or close parentheses ')' only.
// Your job is to check if it is possible to concatenate the two strings in
// some order, that the resulting string will be good.
// A string S is considered to be good if and only if all parentheses in S
// are balanced. For example: the string '(())()' is good, while the string
// '())' is not.
// Return 'Yes' if there's a way to make a good string, and return 'No' otherwise.
// 
// Examples:
// MatchParens(['()(', ')']) == 'Yes'
// MatchParens([')', ')']) == 'No'


func MatchParens(lst []string) string {

    check := func(s string) bool {
        val := 0
        for _, i := range s {
            if i == '(' {
                val++
            } else {
                val--
            }
            if val < 0 {
                return false
            }
        }
        return val == 0
    }

    S1 := lst[0] + lst[1]
    S2 := lst[1] + lst[0]
    if check(S1) || check(S2) {
        return "Yes"
    }
    return "No"
}



   
import (
    "sort"
)

// Given an array arr of integers and a positive integer k, return a sorted list
// of length k with the Maximum k numbers in arr.
// 
// Example 1:
// 
// Input: arr = [-3, -4, 5], k = 3
// Output: [-4, -3, 5]
// 
// Example 2:
// 
// Input: arr = [4, -4, 4], k = 2
// Output: [4, 4]
// 
// Example 3:
// 
// Input: arr = [-3, 2, 1, 2, -1, -2, 1], k = 1
// Output: [2]
// 
// Note:
// 1. The length of the array will be in the range of [1, 1000].
// 2. The elements in the array will be in the range of [-1000, 1000].
// 3. 0 <= k <= len(arr)


func Maximum(arr []int, k int) []int {

    if k == 0 {
        return []int{}
    }
    sort.Slice(arr, func(i, j int) bool {
        return arr[i] < arr[j]
    })
    return arr[len(arr)-k:]
}



   

// Given a non-empty list of integers, return the sum of all of the odd elements that are in even positions.
// 
// Examples
// Solution([5, 8, 7, 1]) ==> 12
// Solution([3, 3, 3, 3, 3]) ==> 9
// Solution([30, 13, 24, 321]) ==>0


func Solution(lst []int) int {

    sum:=0
    for i, x := range lst {
        if i&1==0&&x&1==1 {
            sum+=x
        }
    }
    return sum
}



   
import (
    "strconv"
)

// Given a non-empty array of integers arr and an integer k, return
// the sum of the elements with at most two digits from the first k elements of arr.
// 
// Example:
// 
// Input: arr = [111,21,3,4000,5,6,7,8,9], k = 4
// Output: 24 # sum of 21 + 3
// 
// Constraints:
// 1. 1 <= len(arr) <= 100
// 2. 1 <= k <= len(arr)


func AddElements(arr []int, k int) int {

    sum := 0
    for _, elem := range arr[:k] {
        if len(strconv.Itoa(elem)) <= 2 {
            sum += elem
        }
    }
    return sum
}



   
import (
    "sort"
)

// Given a positive integer n, return a sorted list that has the odd numbers in collatz sequence.
// 
// The Collatz conjecture is a conjecture in mathematics that concerns a sequence defined
// as follows: start with any positive integer n. Then each term is obtained from the
// previous term as follows: if the previous term is even, the next term is one half of
// the previous term. If the previous term is odd, the next term is 3 times the previous
// term plus 1. The conjecture is that no matter what value of n, the sequence will always reach 1.
// 
// Note:
// 1. Collatz(1) is [1].
// 2. returned list sorted in increasing order.
// 
// For example:
// GetOddCollatz(5) returns [1, 5] # The collatz sequence for 5 is [5, 16, 8, 4, 2, 1], so the odd numbers are only 1, and 5.


func GetOddCollatz(n int) []int {

    odd_collatz := make([]int, 0)
    if n&1==1 {
        odd_collatz = append(odd_collatz, n)
    }
    for n > 1 {
        if n &1==0 {
            n>>=1
        } else {
            n = n*3 + 1
        }            
        if n&1 == 1 {
            odd_collatz = append(odd_collatz, n)
        }
    }
    sort.Slice(odd_collatz, func(i, j int) bool {
        return odd_collatz[i] < odd_collatz[j]
    })
    return odd_collatz
}



   
import (
    "strconv"
    "strings"
)

// You have to write a function which validates a given date string and
// returns true if the date is valid otherwise false.
// The date is valid if all of the following rules are satisfied:
// 1. The date string is not empty.
// 2. The number of days is not less than 1 or higher than 31 days for months 1,3,5,7,8,10,12. And the number of days is not less than 1 or higher than 30 days for months 4,6,9,11. And, the number of days is not less than 1 or higher than 29 for the month 2.
// 3. The months should not be less than 1 or higher than 12.
// 4. The date should be in the format: mm-dd-yyyy
// 
// for example:
// ValidDate('03-11-2000') => true
// 
// ValidDate('15-01-2012') => false
// 
// ValidDate('04-0-2040') => false
// 
// ValidDate('06-04-2020') => true
// 
// ValidDate('06/04/2020') => false


func ValidDate(date string) bool {

    isInArray := func(arr []int, i int) bool {
        for _, x := range arr {
            if i == x {
                return true
            }
        }
        return false
    }

    date = strings.TrimSpace(date)
    split := strings.SplitN(date, "-", 3)
    if len(split) != 3 {
        return false
    }
    month, err := strconv.Atoi(split[0])
    if err != nil {
        return false
    }
    day, err := strconv.Atoi(split[1])
    if err != nil {
        return false
    }
    _, err = strconv.Atoi(split[2])
    if err != nil {
        return false
    }
    if month < 1 || month > 12 {
        return false
    }
    
    if isInArray([]int{1,3,5,7,8,10,12}, month) && day < 1 || day > 31 {
        return false
    }
    if isInArray([]int{4,6,9,11}, month) && day < 1 || day > 30 {
        return false
    }
    if month == 2 && day < 1 || day > 29 {
        return false
    }

    return true
}



   
import (
    "strings"
)

// Given a string of words, return a list of words split on whitespace, if no whitespaces exists in the text you
// should split on commas ',' if no commas exists you should return the number of lower-case letters with odd order in the
// alphabet, ord('a') = 0, ord('b') = 1, ... ord('z') = 25
// Examples
// SplitWords("Hello world!") ➞ ["Hello", "world!"]
// SplitWords("Hello,world!") ➞ ["Hello", "world!"]
// SplitWords("abcdef") == 3


func SplitWords(txt string) interface{} {

    if strings.Contains(txt, " ") {
        return strings.Fields(txt)
    } else if strings.Contains(txt, ",") {
        return strings.Split(txt, ",")
    }
    cnt := 0
    for _, r := range txt {
        if 'a' <= r && r <= 'z' && (r-'a')&1==1 {
            cnt++
        }
    }
    return cnt
}



   

// Given a list of numbers, return whether or not they are sorted
// in ascending order. If list has more than 1 duplicate of the same
// number, return false. Assume no negative numbers and only integers.
// 
// Examples
// IsSorted([5]) ➞ true
// IsSorted([1, 2, 3, 4, 5]) ➞ true
// IsSorted([1, 3, 2, 4, 5]) ➞ false
// IsSorted([1, 2, 3, 4, 5, 6]) ➞ true
// IsSorted([1, 2, 3, 4, 5, 6, 7]) ➞ true
// IsSorted([1, 3, 2, 4, 5, 6, 7]) ➞ false
// IsSorted([1, 2, 2, 3, 3, 4]) ➞ true
// IsSorted([1, 2, 2, 2, 3, 4]) ➞ false


func IsSorted(lst []int) bool {

    count_digit := make(map[int]int)
    for _, i := range lst {
        count_digit[i] = 0
    }
    for _, i := range lst {
        count_digit[i]++
    }
    for _, i := range lst {
        if count_digit[i] > 2 {
            return false
        }
    }
    for i := 1;i < len(lst);i++ {
        if lst[i-1] > lst[i] {
            return false
        }
    }
    return true
}
    



   

// You are given two intervals,
// where each interval is a pair of integers. For example, interval = (start, end) = (1, 2).
// The given intervals are closed which means that the interval (start, end)
// includes both start and end.
// For each given interval, it is assumed that its start is less or equal its end.
// Your task is to determine whether the length of Intersection of these two
// intervals is a prime number.
// Example, the Intersection of the intervals (1, 3), (2, 4) is (2, 3)
// which its length is 1, which not a prime number.
// If the length of the Intersection is a prime number, return "YES",
// otherwise, return "NO".
// If the two intervals don't intersect, return "NO".
// 
// 
// [input/output] samples:
// Intersection((1, 2), (2, 3)) ==> "NO"
// Intersection((-1, 1), (0, 4)) ==> "NO"
// Intersection((-3, -1), (-5, 5)) ==> "YES"


func Intersection(interval1 [2]int, interval2 [2]int) string {

    is_prime := func(num int) bool {
        if num == 1 || num == 0 {
            return false
        }
        if num == 2 {
            return true
        }
        for i := 2;i < num;i++ {
            if num%i == 0 {
                return false
            }
        }
        return true
    }
    l := interval1[0]
    if interval2[0] > l {
        l = interval2[0]
    }
    r := interval1[1]
    if interval2[1] < r {
        r = interval2[1]
    }
    length := r - l
    if length > 0 && is_prime(length) {
        return "YES"
    }
    return "NO"
}



   
import (
    "math"
)

// You are given an array arr of integers and you need to return
// sum of magnitudes of integers multiplied by product of all signs
// of each number in the array, represented by 1, -1 or 0.
// Note: return nil for empty arr.
// 
// Example:
// >>> ProdSigns([1, 2, 2, -4]) == -9
// >>> ProdSigns([0, 1]) == 0
// >>> ProdSigns([]) == nil


func ProdSigns(arr []int) interface{} {

    if len(arr) == 0 {
        return nil
    }
    cnt := 0
    sum := 0
    for _, i := range arr {
        if i == 0 {
            return 0
        }
        if i < 0 {
            cnt++
        }
        sum += int(math.Abs(float64(i)))
    }

    prod := int(math.Pow(-1, float64(cnt)))
    return prod * sum
}



   

// Given a grid with N rows and N columns (N >= 2) and a positive integer k,
// each cell of the grid contains a value. Every integer in the range [1, N * N]
// inclusive appears exactly once on the cells of the grid.
// 
// You have to find the minimum path of length k in the grid. You can start
// from any cell, and in each step you can move to any of the neighbor cells,
// in other words, you can go to cells which share an edge with you current
// cell.
// Please note that a path of length k means visiting exactly k cells (not
// necessarily distinct).
// You CANNOT go off the grid.
// A path A (of length k) is considered less than a path B (of length k) if
// after making the ordered lists of the values on the cells that A and B go
// through (let's call them lst_A and lst_B), lst_A is lexicographically less
// than lst_B, in other words, there exist an integer index i (1 <= i <= k)
// such that lst_A[i] < lst_B[i] and for any j (1 <= j < i) we have
// lst_A[j] = lst_B[j].
// It is guaranteed that the answer is unique.
// Return an ordered list of the values on the cells that the minimum path go through.
// 
// Examples:
// 
// Input: grid = [ [1,2,3], [4,5,6], [7,8,9]], k = 3
// Output: [1, 2, 1]
// 
// Input: grid = [ [5,9,3], [4,1,6], [7,8,2]], k = 1
// Output: [1]


func Minpath(grid [][]int, k int) []int {

    n := len(grid)
    val := n * n + 1
    for i:= 0;i < n; i++ {
        for j := 0;j < n;j++ {
            if grid[i][j] == 1 {
                temp := make([]int, 0)
                if i != 0 {
                    temp = append(temp, grid[i - 1][j])
                }

                if j != 0 {
                    temp = append(temp, grid[i][j - 1])
                }

                if i != n - 1 {
                    temp = append(temp, grid[i + 1][j])
                }

                if j != n - 1 {
                    temp = append(temp, grid[i][j + 1])
                }
                for _, x := range temp {
                    if x < val {
                        val = x
                    }
                }
            }
        }
    }

    ans := make([]int, 0, k)
    for i := 0;i < k;i++ {
        if i & 1 == 0 {
            ans = append(ans,  1)
        } else {
            ans = append(ans,  val)
        }
    }
    return ans
}



   

// Everyone knows Fibonacci sequence, it was studied deeply by mathematicians in
// the last couple centuries. However, what people don't know is Tribonacci sequence.
// Tribonacci sequence is defined by the recurrence:
// Tri(1) = 3
// Tri(n) = 1 + n / 2, if n is even.
// Tri(n) =  Tri(n - 1) + Tri(n - 2) + Tri(n + 1), if n is odd.
// For example:
// Tri(2) = 1 + (2 / 2) = 2
// Tri(4) = 3
// Tri(3) = Tri(2) + Tri(1) + Tri(4)
// = 2 + 3 + 3 = 8
// You are given a non-negative integer number n, you have to a return a list of the
// first n + 1 numbers of the Tribonacci sequence.
// Examples:
// Tri(3) = [1, 3, 2, 8]


func Tri(n int) []float64 {

    if n == 0 {
        return []float64{1}
    }
    my_tri := []float64{1, 3}
    for i := 2; i < n + 1; i++ {
        if i &1 == 0 {
            my_tri = append(my_tri, float64(i) / 2 + 1)
        } else {
            my_tri = append(my_tri, my_tri[i - 1] + my_tri[i - 2] + (float64(i) + 3) / 2)
        }
    }
    return my_tri
}



   
import (
    "strconv"
)

// Given a positive integer n, return the product of the odd Digits.
// Return 0 if all Digits are even.
// For example:
// Digits(1)  == 1
// Digits(4)  == 0
// Digits(235) == 15


func Digits(n int) int {

    product := 1
    odd_count := 0
    for _, digit := range strconv.Itoa(n) {
        int_digit := int(digit-'0')
        if int_digit&1 == 1 {
            product= product*int_digit
            odd_count++
        }
    }
    if odd_count==0 {
        return 0
    }
    return product
}



   

// Create a function that takes a string as input which contains only square brackets.
// The function should return true if and only if there is a valid subsequence of brackets
// where at least one bracket in the subsequence is nested.
// 
// IsNested('[[]]') ➞ true
// IsNested('[]]]]]]][[[[[]') ➞ false
// IsNested('[][]') ➞ false
// IsNested('[]') ➞ false
// IsNested('[[][]]') ➞ true
// IsNested('[[]][[') ➞ true


func IsNested(s string) bool {

    opening_bracket_index := make([]int, 0)
    closing_bracket_index := make([]int, 0)
    for i:=0;i < len(s);i++ {
        if s[i] == '[' {
            opening_bracket_index = append(opening_bracket_index, i)
        } else {
            closing_bracket_index = append(closing_bracket_index, i)
        }
    }
    for i := 0;i < len(closing_bracket_index)>>1;i++ {
        closing_bracket_index[i], closing_bracket_index[len(closing_bracket_index)-i-1] = closing_bracket_index[len(closing_bracket_index)-i-1], closing_bracket_index[i]
    }
    cnt := 0
    i := 0
    l := len(closing_bracket_index)
    for _, idx := range opening_bracket_index {
        if i < l && idx < closing_bracket_index[i] {
            cnt++
            i++
        }
    }
    return cnt >= 2
}

    



   
import (
    "math"
)

// You are given a list of numbers.
// You need to return the sum of squared numbers in the given list,
// round each element in the list to the upper int(Ceiling) first.
// Examples:
// For lst = [1,2,3] the output should be 14
// For lst = [1,4,9] the output should be 98
// For lst = [1,3,5,7] the output should be 84
// For lst = [1.4,4.2,0] the output should be 29
// For lst = [-2.4,1,1] the output should be 6


func SumSquares(lst []float64) int {

    squared := 0
    for _, i := range lst {
        squared += int(math.Pow(math.Ceil(i), 2))
    }
    return squared
}



   
import (
    "strings"
)

// Create a function that returns true if the last character
// of a given string is an alphabetical character and is not
// a part of a word, and false otherwise.
// Note: "word" is a group of characters separated by space.
// 
// Examples:
// CheckIfLastCharIsALetter("apple pie") ➞ false
// CheckIfLastCharIsALetter("apple pi e") ➞ true
// CheckIfLastCharIsALetter("apple pi e ") ➞ false
// CheckIfLastCharIsALetter("") ➞ false


func CheckIfLastCharIsALetter(txt string) bool {

    split := strings.Split(txt, " ")
    check := strings.ToLower(split[len(split)-1])
    if len(check) == 1 && 'a' <= check[0] && check[0] <= 'z' {
        return true
    }
    return false
}



   

// Create a function which returns the largest index of an element which
// is not greater than or equal to the element immediately preceding it. If
// no such element exists then return -1. The given array will not contain
// duplicate values.
// 
// Examples:
// CanArrange([1,2,4,3,5]) = 3
// CanArrange([1,2,3]) = -1


func CanArrange(arr []int) int {

    ind:=-1
    i:=1
    for i<len(arr) {
      if arr[i]<arr[i-1] {
        ind=i
      }
      i++
    }
    return ind
}



   

// Create a function that returns a tuple (a, b), where 'a' is
// the largest of negative integers, and 'b' is the smallest
// of positive integers in a list.
// If there is no negative or positive integers, return them as nil.
// 
// Examples:
// LargestSmallestIntegers([2, 4, 1, 3, 5, 7]) == (nil, 1)
// LargestSmallestIntegers([]) == (nil, nil)
// LargestSmallestIntegers([0]) == (nil, nil)


func LargestSmallestIntegers(lst []int) [2]interface{}{

    smallest := make([]int, 0)
    largest := make([]int, 0)
    for _, x := range lst {
        if x < 0 {
            smallest = append(smallest, x)
        } else if x > 0 {
            largest = append(largest, x)
        }
    }
    var result [2]interface{}
    if len(smallest) == 0 {
        result[0] = nil
    } else {
        max := smallest[0]
        for i := 1;i < len(smallest);i++ {
            if smallest[i] > max {
                max = smallest[i]
            }
        }
        result[0] = max
    }
    if len(largest) == 0 {
        result[1] = nil
    } else {
        min := largest[0]
        for i := 1;i < len(largest);i++ {
            if largest[i] < min {
                min = largest[i]
            }
        }
        result[1] = min
    }
    return result
}



   
import (
    "fmt"
    "strconv"
    "strings"
)

// Create a function that takes integers, floats, or strings representing
// real numbers, and returns the larger variable in its given variable type.
// Return nil if the values are equal.
// Note: If a real number is represented as a string, the floating point might be . or ,
// 
// CompareOne(1, 2.5) ➞ 2.5
// CompareOne(1, "2,3") ➞ "2,3"
// CompareOne("5,1", "6") ➞ "6"
// CompareOne("1", 1) ➞ nil


func CompareOne(a, b interface{}) interface{} {

    temp_a := fmt.Sprintf("%v", a)
    temp_b := fmt.Sprintf("%v", b)
    temp_a = strings.ReplaceAll(temp_a, ",", ".")
    temp_b = strings.ReplaceAll(temp_b, ",", ".")
    fa, _ := strconv.ParseFloat(temp_a, 64)
    fb, _ := strconv.ParseFloat(temp_b, 64)
    
    if fa == fb {
        return nil
    }
    if fa > fb {
        return a
    } else {
        return b
    }
}



   

// Evaluate whether the given number n can be written as the sum of exactly 4 positive even numbers
// Example
// IsEqualToSumEven(4) == false
// IsEqualToSumEven(6) == false
// IsEqualToSumEven(8) == true


func IsEqualToSumEven(n int) bool {

    return n&1 == 0 && n >= 8
}



   

// The Brazilian factorial is defined as:
// brazilian_factorial(n) = n! * (n-1)! * (n-2)! * ... * 1!
// where n > 0
// 
// For example:
// >>> SpecialFactorial(4)
// 288
// 
// The function will receive an integer as input and should return the special
// factorial of this integer.


func SpecialFactorial(n int) int {

    fact_i := 1
    special_fact := 1
    for i := 1; i <= n; i++ {
        fact_i *= i
        special_fact *= fact_i
    }
    return special_fact
}



   

// Given a string text, replace all spaces in it with underscores,
// and if a string has more than 2 consecutive spaces,
// then replace all consecutive spaces with -
// 
// FixSpaces("Example") == "Example"
// FixSpaces("Example 1") == "Example_1"
// FixSpaces(" Example 2") == "_Example_2"
// FixSpaces(" Example   3") == "_Example-3"


func FixSpaces(text string) string {

    new_text := make([]byte, 0)
    i := 0
    start, end := 0, 0
    for i < len(text) {
        if text[i] == ' ' {
            end++
        } else {
            switch {
            case end - start > 2:
                new_text = append(new_text, '-')
            case end - start > 0:
                for n := 0;n < end-start;n++ {
                    new_text = append(new_text, '_')
                }
            }
            new_text = append(new_text, text[i])
            start, end = i+1, i+1
        }
        i+=1
    }
    if end - start > 2 {
        new_text = append(new_text, '-')
    } else if end - start > 0 {
        new_text = append(new_text, '_')
    }
    return string(new_text)
}



   
import (
    "strings"
)

// Create a function which takes a string representing a file's name, and returns
// 'Yes' if the the file's name is valid, and returns 'No' otherwise.
// A file's name is considered to be valid if and only if all the following conditions
// are met:
// - There should not be more than three digits ('0'-'9') in the file's name.
// - The file's name contains exactly one dot '.'
// - The substring before the dot should not be empty, and it starts with a letter from
// the latin alphapet ('a'-'z' and 'A'-'Z').
// - The substring after the dot should be one of these: ['txt', 'exe', 'dll']
// Examples:
// FileNameCheck("example.txt") # => 'Yes'
// FileNameCheck("1example.dll") # => 'No' (the name should start with a latin alphapet letter)


func FileNameCheck(file_name string) string {

    suf := []string{"txt", "exe", "dll"}
    lst := strings.Split(file_name, ".")
    isInArray := func (arr []string, x string) bool {
        for _, y := range arr {
            if x == y {
                return true
            }
        }
        return false
    }
    switch {
    case len(lst) != 2:
        return "No"
    case !isInArray(suf, lst[1]):
        return "No"
    case len(lst[0]) == 0:
        return "No"
    case 'a' > strings.ToLower(lst[0])[0] || strings.ToLower(lst[0])[0] > 'z':
        return "No"
    }
    t := 0
    for _, c := range lst[0] {
        if '0' <= c && c <= '9' {
            t++
        }
    }
    if t > 3 {
        return "No"
    }
    return "Yes"
}



   
import (
    "math"
)

// This function will take a list of integers. For all entries in the list, the function shall square the integer entry if its index is a
// multiple of 3 and will cube the integer entry if its index is a multiple of 4 and not a multiple of 3. The function will not
// change the entries in the list whose indexes are not a multiple of 3 or 4. The function shall then return the sum of all entries.
// 
// Examples:
// For lst = [1,2,3] the output should be 6
// For lst = []  the output should be 0
// For lst = [-1,-5,2,-1,-5]  the output should be -126


func SumSquares(lst []int) int {

    result := make([]int, 0)
    for i := 0;i < len(lst);i++ {
        switch {
        case i %3 == 0:
            result = append(result, int(math.Pow(float64(lst[i]), 2)))
        case i % 4 == 0 && i%3 != 0:
            result = append(result, int(math.Pow(float64(lst[i]), 3)))
        default:
            result = append(result, lst[i])
        }
    }
    sum := 0
    for _, x := range result {
        sum += x
    }
    return sum
}



   
import (
    "strings"
)

// You are given a string representing a sentence,
// the sentence contains some words separated by a space,
// and you have to return a string that contains the words from the original sentence,
// whose lengths are prime numbers,
// the order of the words in the new string should be the same as the original one.
// 
// Example 1:
// Input: sentence = "This is a test"
// Output: "is"
// 
// Example 2:
// Input: sentence = "lets go for swimming"
// Output: "go for"
// 
// Constraints:
// * 1 <= len(sentence) <= 100
// * sentence contains only letters


func WordsInSentence(sentence string) string {

    new_lst := make([]string, 0)
    for _, word := range strings.Fields(sentence) {
        flg := 0
        if len(word) == 1 {
            flg = 1
        }
        for i := 2;i < len(word);i++ {
            if len(word)%i == 0 {
                flg = 1
            }
        }
        if flg == 0 || len(word) == 2 {
            new_lst = append(new_lst, word)
        }
    }
    return strings.Join(new_lst, " ")
}



   
import (
    "strconv"
    "strings"
)

// Your task is to implement a function that will Simplify the expression
// x * n. The function returns true if x * n evaluates to a whole number and false
// otherwise. Both x and n, are string representation of a fraction, and have the following format,
// <numerator>/<denominator> where both numerator and denominator are positive whole numbers.
// 
// You can assume that x, and n are valid fractions, and do not have zero as denominator.
// 
// Simplify("1/5", "5/1") = true
// Simplify("1/6", "2/1") = false
// Simplify("7/10", "10/2") = false


func Simplify(x, n string) bool {

    xx := strings.Split(x, "/")
    nn := strings.Split(n, "/")
    a, _ := strconv.Atoi(xx[0])
    b, _ := strconv.Atoi(xx[1])
    c, _ := strconv.Atoi(nn[0])
    d, _ := strconv.Atoi(nn[1])
    numerator := float64(a*c)
    denom := float64(b*d)
    return numerator/denom == float64(int(numerator/denom))
}



   
import (
    "sort"
    "strconv"
)

// Write a function which sorts the given list of integers
// in ascending order according to the sum of their digits.
// Note: if there are several items with similar sum of their digits,
// order them based on their index in original list.
// 
// For example:
// >>> OrderByPoints([1, 11, -1, -11, -12]) == [-1, -11, 1, -12, 11]
// >>> OrderByPoints([]) == []


func OrderByPoints(nums []int) []int {

    digits_sum := func (n int) int {
        neg := 1
        if n < 0 {
            n, neg = -1 * n, -1 
        }
        sum := 0
        for i, c := range strconv.Itoa(n) {
            if i == 0 {
                sum += int(c-'0')*neg
            } else {
                sum += int(c-'0')
            }
        }
        return sum
    }
    sort.SliceStable(nums, func(i, j int) bool {
        return digits_sum(nums[i]) < digits_sum(nums[j])
    })
    return nums
}



   
import (
    "strconv"
)

// Write a function that takes an array of numbers as input and returns
// the number of elements in the array that are greater than 10 and both
// first and last digits of a number are odd (1, 3, 5, 7, 9).
// For example:
// Specialfilter([15, -73, 14, -15]) => 1
// Specialfilter([33, -2, -3, 45, 21, 109]) => 2


func Specialfilter(nums []int) int {

    count := 0
    for _, num := range nums {
        if num > 10 {
            number_as_string := strconv.Itoa(num)
            if number_as_string[0]&1==1 && number_as_string[len(number_as_string)-1]&1==1 {
                count++
            }
        }
    }        
    return count
}



   

// You are given a positive integer n. You have to create an integer array a of length n.
// For each i (1 ≤ i ≤ n), the value of a[i] = i * i - i + 1.
// Return the number of triples (a[i], a[j], a[k]) of a where i < j < k,
// and a[i] + a[j] + a[k] is a multiple of 3.
// 
// Example :
// Input: n = 5
// Output: 1
// Explanation:
// a = [1, 3, 7, 13, 21]
// The only valid triple is (1, 7, 13).


func GetMaxTriples(n int) int {

    A := make([]int, 0)
    for i := 1;i <= n;i++ {
        A = append(A, i*i-i+1)
    }
    ans := 0
    for i := 0;i < n;i++ {
        for j := i + 1;j < n;j++ {
            for k := j + 1;k < n;k++ {
                if (A[i]+A[j]+A[k])%3 == 0 {
                    ans++
                }
            }
        }
    }
    return ans
}



   

// There are eight planets in our solar system: the closerst to the Sun
// is Mercury, the next one is Venus, then Earth, Mars, Jupiter, Saturn,
// Uranus, Neptune.
// Write a function that takes two planet names as strings planet1 and planet2.
// The function should return a tuple containing all planets whose orbits are
// located between the orbit of planet1 and the orbit of planet2, sorted by
// the proximity to the sun.
// The function should return an empty tuple if planet1 or planet2
// are not correct planet names.
// Examples
// Bf("Jupiter", "Neptune") ==> ("Saturn", "Uranus")
// Bf("Earth", "Mercury") ==> ("Venus")
// Bf("Mercury", "Uranus") ==> ("Venus", "Earth", "Mars", "Jupiter", "Saturn")


func Bf(planet1, planet2 string) []string {

    planet_names := []string{"Mercury", "Venus", "Earth", "Mars", "Jupiter", "Saturn", "Uranus", "Neptune"}
    pos1 := -1
    pos2 := -1
    for i, x := range planet_names {
        if planet1 == x {
            pos1 = i
        }
        if planet2 == x {
            pos2 = i
        }
    }
    if pos1 == -1 || pos2 == -1 || pos1 == pos2 {
        return []string{}
    }
    if pos1 < pos2 {
        return planet_names[pos1 + 1: pos2]
    }
    return planet_names[pos2 + 1 : pos1]
}



   
import (
    "sort"
)

// Write a function that accepts a list of strings as a parameter,
// deletes the strings that have odd lengths from it,
// and returns the resulted list with a sorted order,
// The list is always a list of strings and never an array of numbers,
// and it may contain duplicates.
// The order of the list should be ascending by length of each word, and you
// should return the list sorted by that rule.
// If two words have the same length, sort the list alphabetically.
// The function should return a list of strings in sorted order.
// You may assume that all words will have the same length.
// For example:
// assert list_sort(["aa", "a", "aaa"]) => ["aa"]
// assert list_sort(["ab", "a", "aaa", "cd"]) => ["ab", "cd"]


func SortedListSum(lst []string) []string {

    sort.SliceStable(lst, func(i, j int) bool {
        return lst[i] < lst[j]
    })
    new_lst := make([]string, 0)
    for _, i := range lst {
        if len(i)&1==0 {
            new_lst = append(new_lst, i)
        }
    }
    sort.SliceStable(new_lst, func(i, j int) bool {
        return len(new_lst[i]) < len(new_lst[j])
    })
    return new_lst
}



   

// A simple program which should return the value of x if n is
// a prime number and should return the value of y otherwise.
// 
// Examples:
// for XOrY(7, 34, 12) == 34
// for XOrY(15, 8, 5) == 5


func XOrY(n, x, y int) int {

    if n == 1 {
        return y
    }
    for i := 2;i < n;i++ {
        if n % i == 0 {
            return y
        }
    }
    return x
}



   
import (
    "math"
)

// Given a list of numbers, return the sum of squares of the numbers
// in the list that are odd. Ignore numbers that are negative or not integers.
// 
// DoubleTheDifference([1, 3, 2, 0]) == 1 + 9 + 0 + 0 = 10
// DoubleTheDifference([-1, -2, 0]) == 0
// DoubleTheDifference([9, -2]) == 81
// DoubleTheDifference([0]) == 0
// 
// If the input list is empty, return 0.


func DoubleTheDifference(lst []float64) int {

    sum := 0
    for _, i := range lst {
        if i > 0 && math.Mod(i, 2) != 0 && i == float64(int(i)) {
            sum += int(math.Pow(i, 2))
        }
    }
    return sum
}



   
import (
    "math"
)

// I think we all remember that feeling when the result of some long-awaited
// event is finally known. The feelings and thoughts you have at that moment are
// definitely worth noting down and comparing.
// Your task is to determine if a person correctly guessed the results of a number of matches.
// You are given two arrays of scores and guesses of equal length, where each index shows a match.
// Return an array of the same length denoting how far off each guess was. If they have guessed correctly,
// the value is 0, and if not, the value is the absolute difference between the guess and the score.
// 
// 
// example:
// 
// Compare([1,2,3,4,5,1],[1,2,3,4,2,-2]) -> [0,0,0,0,3,3]
// Compare([0,5,0,0,0,4],[4,1,1,0,0,-2]) -> [4,4,1,0,0,6]


func Compare(game,guess []int) []int {

    ans := make([]int, 0, len(game))
    for i := range game {
        ans = append(ans, int(math.Abs(float64(game[i]-guess[i]))))
    }
    return ans
}



   
import (
    "math"
)

// You will be given the name of a class (a string) and a list of extensions.
// The extensions are to be used to load additional classes to the class. The
// strength of the extension is as follows: Let CAP be the number of the uppercase
// letters in the extension's name, and let SM be the number of lowercase letters
// in the extension's name, the strength is given by the fraction CAP - SM.
// You should find the strongest extension and return a string in this
// format: ClassName.StrongestExtensionName.
// If there are two or more extensions with the same strength, you should
// choose the one that comes first in the list.
// For example, if you are given "Slices" as the class and a list of the
// extensions: ['SErviNGSliCes', 'Cheese', 'StuFfed'] then you should
// return 'Slices.SErviNGSliCes' since 'SErviNGSliCes' is the strongest extension
// (its strength is -1).
// Example:
// for StrongestExtension('my_class', ['AA', 'Be', 'CC']) == 'my_class.AA'


func StrongestExtension(class_name string, extensions []string) string {

    strong := extensions[0]
    
    my_val := math.MinInt
    for _, s := range extensions {
        cnt0, cnt1 := 0, 0
        for _, c := range s {
            switch {
            case 'A' <= c && c <= 'Z':
                cnt0++
            case 'a' <= c && c <= 'z':
                cnt1++
            }
        }
        val := cnt0-cnt1
        if val > my_val {
            strong = s
            my_val = val
        }
    }
    return class_name + "." + strong
}



   

// You are given 2 words. You need to return true if the second word or any of its rotations is a substring in the first word
// CycpatternCheck("abcd","abd") => false
// CycpatternCheck("hello","ell") => true
// CycpatternCheck("whassup","psus") => false
// CycpatternCheck("abab","baa") => true
// CycpatternCheck("efef","eeff") => false
// CycpatternCheck("himenss","simen") => true


func CycpatternCheck(a , b string) bool {

    l := len(b)
    pat := b + b
    for i := 0;i < len(a) - l + 1; i++ {
        for j := 0;j<l + 1;j++ {
            if a[i:i+l] == pat[j:j+l] {
                return true
            }
        }
    }
    return false
}



   
import (
    "strconv"
)

// Given an integer. return a tuple that has the number of even and odd digits respectively.
// 
// Example:
// EvenOddCount(-12) ==> (1, 1)
// EvenOddCount(123) ==> (1, 2)


func EvenOddCount(num int) [2]int {

    even_count := 0
    odd_count := 0
    if num < 0 {
        num = -num
    }
    for _, r := range strconv.Itoa(num) {
        if r&1==0 {
            even_count++
        } else {
            odd_count++
        }
    }
    return [2]int{even_count, odd_count}
}



   
import (
    "strings"
)

// Given a positive integer, obtain its roman numeral equivalent as a string,
// and return it in lowercase.
// Restrictions: 1 <= num <= 1000
// 
// Examples:
// >>> IntToMiniRoman(19) == 'xix'
// >>> IntToMiniRoman(152) == 'clii'
// >>> IntToMiniRoman(426) == 'cdxxvi'


func IntToMiniRoman(number int) string {

    num := []int{1, 4, 5, 9, 10, 40, 50, 90,  
           100, 400, 500, 900, 1000}
    sym := []string{"I", "IV", "V", "IX", "X", "XL",  
           "L", "XC", "C", "CD", "D", "CM", "M"}
    i := 12
    res := ""
    for number != 0 {
        div := number / num[i] 
        number %= num[i] 
        for div != 0 {
            res += sym[i] 
            div--
        }
        i--
    }
    return strings.ToLower(res)
}



   

// Given the lengths of the three sides of a triangle. Return true if the three
// sides form a right-angled triangle, false otherwise.
// A right-angled triangle is a triangle in which one angle is right angle or
// 90 degree.
// Example:
// RightAngleTriangle(3, 4, 5) == true
// RightAngleTriangle(1, 2, 3) == false


func RightAngleTriangle(a, b, c int) bool {

    return a*a == b*b + c*c || b*b == a*a + c*c || c*c == a*a + b*b
}



   
import (
    "sort"
)

// Write a function that accepts a list of strings.
// The list contains different words. Return the word with maximum number
// of unique characters. If multiple strings have maximum number of unique
// characters, return the one which comes first in lexicographical order.
// 
// FindMax(["name", "of", "string"]) == "string"
// FindMax(["name", "enam", "game"]) == "enam"
// FindMax(["aaaaaaa", "bb" ,"cc"]) == ""aaaaaaa"


func FindMax(words []string) string {

    key := func (word string) (int, string) {
        set := make(map[rune]struct{})
        for _, r := range word {
            set[r] = struct{}{}
        }
        return -len(set), word
    }
    sort.SliceStable(words, func(i, j int) bool {
        ia, ib := key(words[i])
        ja, jb := key(words[j])
        if ia == ja {
            return ib < jb
        }
        return ia < ja
    })
    return words[0]
}



   

// You're a hungry rabbit, and you already have Eaten a certain number of carrots,
// but now you need to Eat more carrots to complete the day's meals.
// you should return an array of [ total number of Eaten carrots after your meals,
// the number of carrots left after your meals ]
// if there are not enough remaining carrots, you will Eat all remaining carrots, but will still be hungry.
// 
// Example:
// * Eat(5, 6, 10) -> [11, 4]
// * Eat(4, 8, 9) -> [12, 1]
// * Eat(1, 10, 10) -> [11, 0]
// * Eat(2, 11, 5) -> [7, 0]
// 
// Variables:
// @number : integer
// the number of carrots that you have Eaten.
// @need : integer
// the number of carrots that you need to Eat.
// @remaining : integer
// the number of remaining carrots thet exist in stock
// 
// Constrain:
// * 0 <= number <= 1000
// * 0 <= need <= 1000
// * 0 <= remaining <= 1000
// 
// Have fun :)


func Eat(number, need, remaining int) []int {

    if(need <= remaining) {
        return []int{ number + need , remaining-need }
    }
    return []int{ number + remaining , 0}
}



   
import (
    "math"
)

// Given two lists operator, and operand. The first list has basic algebra operations, and
// the second list is a list of integers. Use the two given lists to build the algebric
// expression and return the evaluation of this expression.
// 
// The basic algebra operations:
// Addition ( + )
// Subtraction ( - )
// Multiplication ( * )
// Floor division ( // )
// Exponentiation ( ** )
// 
// Example:
// operator['+', '*', '-']
// array = [2, 3, 4, 5]
// result = 2 + 3 * 4 - 5
// => result = 9
// 
// Note:
// The length of operator list is equal to the length of operand list minus one.
// Operand is a list of of non-negative integers.
// Operator list has at least one operator, and operand list has at least two operands.


func DoAlgebra(operator []string, operand []int) int {

    higher := func(a, b string) bool {
        if b == "*" || b == "//" || b == "**" {
            return false
        }
        if a == "*" || a == "//" || a == "**" {
            return true
        }
        return false
    }
    for len(operand) > 1 {
        pos := 0
        sign := operator[0]
        for i, str := range operator {
            if higher(str, sign) {
                sign = str
                pos = i
            }
        }
        switch sign {
        case "+":
            operand[pos] += operand[pos+1]
        case "-":
            operand[pos] -= operand[pos+1]
        case "*":
            operand[pos] *= operand[pos+1]
        case "//":
            operand[pos] /= operand[pos+1]
        case "**":
            operand[pos] = int(math.Pow(float64(operand[pos]), float64(operand[pos+1])))
        }
        operator = append(operator[:pos], operator[pos+1:]...)
        operand = append(operand[:pos+1], operand[pos+2:]...)
    }
    return operand [0]
}



   

// You are given a string s.
// if s[i] is a letter, reverse its case from lower to upper or vise versa,
// otherwise keep it as it is.
// If the string contains no letters, reverse the string.
// The function should return the resulted string.
// Examples
// Solve("1234") = "4321"
// Solve("ab") = "AB"
// Solve("#a@C") = "#A@c"


func Solve(s string) string {

    flg := 0
    new_str := []rune(s)
    for i, r := range new_str {
        if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
            if 'a' <= r && r <= 'z' {
                new_str[i] = r - 'a' + 'A'
            } else {
                new_str[i] = r - 'A' + 'a'
            }
            flg = 1
        }
    }
    if flg == 0 {
        for i := 0;i < len(new_str)>>1;i++ {
            new_str[i], new_str[len(new_str)-i-1] = new_str[len(new_str)-i-1], new_str[i]
        }
    }
    return string(new_str)
}



   
import (
    "crypto/md5"
    "fmt"
)

// Given a string 'text', return its md5 hash equivalent string.
// If 'text' is an empty string, return nil.
// 
// >>> StringToMd5('Hello world') == '3e25960a79dbc69b674cd4ec67a72c62'


func StringToMd5(text string) interface{} {

    if text == "" {
        return nil
    }
    return fmt.Sprintf("%x", md5.Sum([]byte(text)))
}



   

// Given two positive integers a and b, return the even digits between a
// and b, in ascending order.
// 
// For example:
// GenerateIntegers(2, 8) => [2, 4, 6, 8]
// GenerateIntegers(8, 2) => [2, 4, 6, 8]
// GenerateIntegers(10, 14) => []


func GenerateIntegers(a, b int) []int {

    min := func (a, b int) int {
        if a > b {
            return b
        }
        return a
    }
    max := func (a, b int) int {
        if a > b {
            return a
        }
        return b
    }
    lower := max(2, min(a, b))
    upper := min(8, max(a, b))
    ans := make([]int, 0)
    for i := lower;i <= upper;i++ {
        if i&1==0 {
            ans = append(ans, i)
        }
    }
    return ans
}








// Initialize a Gin router and start the server on port 8080.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Define a simple GET route that responds with a JSON message.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "pong",
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Define a simple POST route that responds with a success message.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.POST("/submit", func(c *gin.Context) {
        c.String(200, "Posted successfully")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Extract a path parameter and respond with a greeting message.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/user/:name", func(c *gin.Context) {
        name := c.Param("name")
        c.String(200, "Hello %s", name)
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Extract query parameters and respond with a personalized greeting.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/welcome", func(c *gin.Context) {
        firstname := c.DefaultQuery("firstname", "Guest")
        lastname := c.Query("lastname")
        c.String(200, "Hello %s %s", firstname, lastname)
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Group routes under a common path prefix.
package main

import "github.com/gin-gonic/gin"

func loginEndpoint(c *gin.Context) {
    c.String(200, "Login")
}

func submitEndpoint(c *gin.Context) {
    c.String(200, "Submit")
}

func main() {
    r := gin.Default()
    api := r.Group("/api")
    {
        api.GET("/login", loginEndpoint)
        api.GET("/submit", submitEndpoint)
    }
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Respond with a JSON object.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/json", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "hey", "status": 200})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Respond with an XML object.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/xml", func(c *gin.Context) {
        c.XML(200, gin.H{"message": "hey", "status": 200})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Render an HTML template.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.LoadHTMLGlob("templates/*")
    r.GET("/index", func(c *gin.Context) {
        c.HTML(200, "index.tmpl", gin.H{
            "title": "Main website",
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Serve static files from a directory.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Static("/assets", "./assets")
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Use default logger and recovery middleware.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Use(gin.Logger())
    r.Use(gin.Recovery())
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Define and use a custom middleware.
package main

import "github.com/gin-gonic/gin"

func AuthRequired() gin.HandlerFunc {
    return func(c *gin.Context) {
        // logic here
        c.Next()
    }
}

func main() {
    r := gin.Default()
    r.Use(AuthRequired())
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Handle a form POST request.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.POST("/form_post", func(c *gin.Context) {
        message := c.PostForm("message")
        nick := c.DefaultPostForm("nick", "anonymous")
        c.JSON(200, gin.H{"status": "posted", "message": message, "nick": nick})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Handle a file upload request.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.POST("/upload", func(c *gin.Context) {
        file, _ := c.FormFile("file")
        c.SaveUploadedFile(file, "/tmp/"+file.Filename)
        c.String(200, "File uploaded successfully")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Redirect to an external URL.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/redirect", func(c *gin.Context) {
        c.Redirect(301, "http://www.google.com/")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Define a custom handler for unknown routes.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.NoRoute(func(c *gin.Context) {
        c.JSON(404, gin.H{"message": "Not Found"})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Recover from panics to avoid crashing the server.
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
)

func main() {
    defer func() {
        if err := recover(); err != nil {
            fmt.Println("Recovered from panic:", err)
        }
    }()

    r := gin.Default()
    r.GET("/panic", func(c *gin.Context) {
        panic("An unexpected error occurred!")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Bind JSON payload to a struct.
package main

import (
    "github.com/gin-gonic/gin"
)

type Login struct {
    User     string `json:"user" binding:"required"`
    Password string `json:"password" binding:"required"`
}

func main() {
    r := gin.Default()
    r.POST("/login", func(c *gin.Context) {
        var json Login
        if err := c.ShouldBindJSON(&json); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"status": "you are logged in"})
    })
    r.Run // listen and serve on 0.0.0.0:8080
}



// Bind form data to a struct.
package main

import (
    "github.com/gin-gonic/gin"
)

type Login struct {
    User     string `form:"user" binding:"required"`
    Password string `form:"password" binding:"required"`
}

func main() {
    r := gin.Default()
    r.POST("/login", func(c *gin.Context) {
        var form Login
        if err := c.ShouldBind(&form); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"status": "you are logged in"})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Bind URI parameters to a struct.
package main

import (
    "github.com/gin-gonic/gin"
)

type Person struct {
    Name string `uri:"name" binding:"required"`
    ID   string `uri:"id" binding:"required,uuid"`
}

func main() {
    r := gin.Default()
    r.GET("/person/:name/:id", func(c *gin.Context) {
        var person Person
        if err := c.ShouldBindUri(&person); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"name": person.Name, "uuid": person.ID})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}



// Define a custom validation function.
package main

import (
    "gopkg.in/go-playground/validator.v8"
    "github.com/gin-gonic/gin"
)

type Booking struct {
    CheckIn  string `form:"check_in" binding:"required,bookabledate"`
    CheckOut string `form:"check_out" binding:"required,gtfield=CheckIn"`
}

func bookableDate(
    v *validator.Validate, topStruct interface{}, currentStructField interface{},
    field interface{}, param string) bool {
    // Custom validation logic here.
    return true
}

func main() {
    r := gin.Default()
    if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
        v.RegisterValidation("bookabledate", bookableDate)
    }

    r.POST("/book", func(c *gin.Context) {
        var b Booking
        if err := c.ShouldBind(&b); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"message": "Booking dates are valid!"})
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}




// Set and retrieve a context key.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Use(func(c *gin.Context) {
        c.Set("example", "12345")
        c.Next()
    })

    r.GET("/context", func(c *gin.Context) {
        example := c.MustGet("example").(string)
        c.JSON(200, gin.H{"example": example})
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}



// Use a context copy for asynchronous operations.
package main

import (
    "log"
    "time"

    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/long_async", func(c *gin.Context) {
        cCp := c.Copy()
        go func() {
            time.Sleep(5 * time.Second)
            log.Println("Done! in path " + cCp.Request.URL.Path)
        }()
        c.String(200, "working")
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}



// Serve a file for download.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/download", func(c *gin.Context) {
        c.File("/tmp/file.txt")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Respond with an HTML string.
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/html", func(c *gin.Context) {
        c.Data(200, "text/html; charset=utf-8", []byte("<html><body>Hello, World!</body></html>"))
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Use a custom render function.
package main

import (
    "github.com/gin-gonic/gin"
)

type JSONP struct {
    Callback string
    Data     interface{}
}

func (r JSONP) Render(w http.ResponseWriter) error {
    if callback := r.Callback; callback != "" {
        w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
        _, err := w.Write([]byte(callback + "("))
        if err != nil {
            return err
        }
        json.NewEncoder(w).Encode(r.Data)
        _, err = w.Write([]byte(");"))
        return err
    }
    return nil
}

func (r JSONP) WriteContentType(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
}

func main() {
    r := gin.Default()
    r.GET("/JSONP", func(c *gin.Context) {
        c.Render(200, JSONP{Callback: "callback", Data: gin.H{"foo": "bar"}})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Log incoming requests using the default writer.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.Use(gin.LoggerWithWriter(gin.DefaultWriter))
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Use secure middleware to enforce SSL.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/unrolled/secure"
)

func main() {
    r := gin.Default()
    r.Use(func() gin.HandlerFunc {
        return secure.New(secure.Config{
            SSLRedirect: true,
        }).Handler
    }())
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Apply rate limiting to requests.
package main

import (
    "github.com/didip/tollbooth"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    limiter := tollbooth.NewLimiter(1, nil)

    r.Use(func(c *gin.Context) {
        httpError := tollbooth.LimitByRequest(limiter, c.Writer, c.Request)
        if httpError != nil {
            c.String(httpError.StatusCode, httpError.Message)
            c.Abort()
            return
        }
        c.Next()
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}




// Use basic authentication for routes.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.Use(gin.BasicAuth(gin.Accounts{
        "foo": "bar",
    }))
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Set custom template functions.
package main

import (
    "github.com/gin-gonic/gin"
    "html/template"
    "time"
)

func main() {
    r := gin.Default()
    r.SetFuncMap(template.FuncMap{
        "formatAsDate": func(t time.Time) string {
            return t.Format("2006-01-02")
        },
    })
    r.LoadHTMLGlob("templates/*")
    r.GET("/date", func(c *gin.Context) {
        c.HTML(200, "date.tmpl", gin.H{
            "now": time.Now(),
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Handle file upload with progress information.
package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func main() {
    r := gin.Default()
    r.POST("/upload", func(c *gin.Context) {
        file, err := c.FormFile("file")
        if err != nil {
            c.String(http.StatusBadRequest, "Bad request")
            return
        }

        c.String(http.StatusOK, "Uploaded successfully %s", file.Filename)
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Set custom headers in the response.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/headers", func(c *gin.Context) {
        c.Header("Content-Type", "application/json")
        c.Header("X-Custom-Header", "value")
        c.JSON(200, gin.H{"message": "Headers set"})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Apply GZIP middleware to compress responses.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/gzip"
)

func main() {
    r := gin.Default()
    r.Use(gzip.Gzip(gzip.DefaultCompression))
    r.GET("/gzip", func(c *gin.Context) {
        c.String(200, "This is a compressed response")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Add request ID middleware to track requests.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/requestid"
)

func main() {
    r := gin.Default()
    r.Use(requestid.New())
    r.GET("/request_id", func(c *gin.Context) {
        id := requestid.Get(c)
        c.JSON(200, gin.H{"request_id": id})
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Implement rate limiting using Gin middleware.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/limiter"
    "github.com/ulule/limiter/v3"
    "github.com/ulule/limiter/v3/drivers/store/memory"
)

func main() {
    r := gin.Default()
    rate := limiter.Rate{
        Period: 1 * time.Second,
        Limit:  1,
    }
    store := memory.NewStore()
    instance := limiter.New(store, rate)
    r.Use(limiter.NewMiddleware(instance))
    r.GET("/limited", func(c *gin.Context) {
        c.String(200, "This is a rate-limited route")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Use localization middleware for multi-language support.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/nicksnyder/go-i18n/v2/i18n"
    "golang.org/x/text/language"
    "github.com/gin-contrib/multitemplate"
)

func main() {
    r := gin.Default()
    bundle := i18n.NewBundle(language.English)
    bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
    localizer := i18n.NewLocalizer(bundle, "en")

    r.Use(func(c *gin.Context) {
        c.Set("localizer", localizer)
        c.Next()
    })

    r.GET("/hello", func(c *gin.Context) {
        localizer := c.MustGet("localizer").(*i18n.Localizer)
        message := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "Hello"})
        c.String(200, message)
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}




// Version routes using URL prefixes.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    v1 := r.Group("/v1")
    {
        v1.GET("/hello", func(c *gin.Context) {
            c.String(200, "Hello from v1")
        })
    }
    v2 := r.Group("/v2")
    {
        v2.GET("/hello", func(c *gin.Context) {
            c.String(200, "Hello from v2")
        })
    }
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Serve custom error pages for different status codes.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.NoRoute(func(c *gin.Context) {
        c.HTML(404, "404.html", nil)
    })
    r.LoadHTMLGlob("templates/*")
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Stream a response to the client.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/stream", func(c *gin.Context) {
        c.Stream(func(w io.Writer) bool {
            for i := 0; i < 10; i++ {
                fmt.Fprintf(w, "data %d\n", i)
                time.Sleep(1 * time.Second)
            }
            return false
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Use a custom log formatter for the logger.
package main

import (
    "github.com/gin-gonic/gin"
    "time"
)

func main() {
    r := gin.Default()
    r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
        return fmt.Sprintf("[%s] %s %s %d %s\n",
            param.TimeStamp.Format(time.RFC822),
            param.ClientIP,
            param.Method,
            param.StatusCode,
            param.Latency,
        )
    }))
    r.GET("/ping", func(c *gin.Context) {
        c.String(200, "pong")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Validate route parameters using middleware.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-gonic/gin/binding"
    "gopkg.in/go-playground/validator.v8"
)

func main() {
    r := gin.Default()
    if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
        v.RegisterValidation("custom", func(
            v *validator.Validate, topStruct interface{}, field interface{},
            param string) bool {
            return field.(string) == "custom"
        })
    }

    r.GET("/validate/:param", func(c *gin.Context) {
        param := c.Param("param")
        if param != "custom" {
            c.JSON(400, gin.H{"error": "invalid parameter"})
            return
        }
        c.JSON(200, gin.H{"message": "valid parameter"})
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}




// Implement IP whitelisting for access control.
package main

import (
    "github.com/gin-gonic/gin"
    "net"
)

func main() {
    r := gin.Default()
    r.Use(func(c *gin.Context) {
        whitelist := []string{"127.0.0.1", "192.168.1.1"}
        clientIP := net.ParseIP(c.ClientIP())
        for _, ip := range whitelist {
            if clientIP.Equal(net.ParseIP(ip)) {
                c.Next()
                return
            }
        }
        c.JSON(403, gin.H{"error": "IP not whitelisted"})
        c.Abort()
    })
    r.GET("/protected", func(c *gin.Context) {
        c.String(200, "You have access")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Apply request throttling using a simple counter.
package main

import (
    "github.com/gin-gonic/gin"
    "time"
)

func main() {
    r := gin.Default()
    var counter int
    r.Use(func(c *gin.Context) {
        counter++
        if counter > 100 {
            c.JSON(429, gin.H{"error": "too many requests"})
            c.Abort()
            return
        }
        time.AfterFunc(1*time.Minute, func() {
            counter--
        })
        c.Next()
    })
    r.GET("/throttled", func(c *gin.Context) {
        c.String(200, "This is a throttled route")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Implement Server-Sent Events (SSE) with Gin.
package main

import (
    "github.com/gin-gonic/gin"
    "time"
)

func main() {
    r := gin.Default()
    r.GET("/sse", func(c *gin.Context) {
        c.Stream(func(w io.Writer) bool {
            for i := 0; i < 10; i++ {
                fmt.Fprintf(w, "data: %d\n\n", i)
                time.Sleep(1 * time.Second)
            }
            return false
        })
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Apply CORS middleware to allow cross-origin requests.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/cors"
)

func main() {
    r := gin.Default()
    r.Use(cors.New(cors.Config{
        AllowOrigins:     []string{"http://example.com"},
        AllowMethods:     []string{"GET", "POST"},
        AllowHeaders:     []string{"Origin"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
    }))
    r.GET("/cors", func(c *gin.Context) {
        c.String(200, "CORS enabled")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Serve static files from a directory.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.Static("/static", "./static")
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Manage user sessions with Gin.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
)

func main() {
    r := gin.Default()
    store := cookie.NewStore([]byte("secret"))
    r.Use(sessions.Sessions("mysession", store))

    r.GET("/session", func(c *gin.Context) {
        session := sessions.Default(c)
        session.Set("foo", "bar")
        session.Save()
        c.JSON(200, gin.H{"message": "session saved"})
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}




// Add a health check endpoint to monitor service status.
package main

import (
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/health", func(c *gin.Context) {
        c.String(200, "OK")
    })
    r.Run() // listen and serve on 0.0.0.0:8080
}




// Implement simple cache middleware.
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/patrickmn/go-cache"
    "time"
)

func main() {
    r := gin.Default()
    c := cache.New(5*time.Minute, 10*time.Minute)
    r.Use(func(c *gin.Context) {
        if data, found := c.Get(c.Request.RequestURI); found {
            c.JSON(200, data)
            c.Abort()
            return
        }
        c.Next()
        c.Set(c.Request.RequestURI, c.Writer.Body)
    })

    r.GET("/cached", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "This is a cached response"})
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}












// Basic Go Kit service setup
package main

import (
	"context"
	"net/http"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type StringService struct{}

func (StringService) Uppercase(_ context.Context, s string) (string, error) {
	return strings.ToUpper(s), nil
}

func makeUppercaseEndpoint(svc StringService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(string)
		v, err := svc.Uppercase(ctx, req)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseHandler := httptransport.NewServer(
		makeUppercaseEndpoint(svc),
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)
	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Logging middleware for Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func loggingMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			start := time.Now()
			response, err := next(ctx, request)
			logger.Log("request", request, "response", response, "took", time.Since(start))
			return response, err
		}
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := loggingMiddleware(logger)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Basic Go Kit client example
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	u, _ := url.Parse("http://localhost:8080/uppercase")
	client := httptransport.NewClient(
		"POST",
		u,
		func(_ context.Context, r *http.Request, request interface{}) error {
			s := request.(string)
			r.Body = ioutil.NopCloser(strings.NewReader(s))
			return nil
		},
		func(_ context.Context, r *http.Response) (interface{}, error) {
			var response string
			if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
				return nil, err
			}
			return response, nil
		},
	).Endpoint()

	response, err := client(context.Background(), "hello")
	if err != nil {
		logger.Log("err", err)
		return
	}
	fmt.Println(response)
}






// Instrumentation middleware for Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/prometheus"
	httptransport "github.com/go-kit/kit/transport/http"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

func instrumentationMiddleware(requestCount metrics.Counter, duration metrics.Histogram) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			defer func(begin time.Time) {
				requestCount.Add(1)
				duration.Observe(time.Since(begin).Seconds())
			}(time.Now())
			return next(ctx, request)
		}
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	requestCount := prometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "example",
		Subsystem: "string_service",
		Name:      "request_count",
	}, []string{})
	duration := prometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
		Namespace: "example",
		Subsystem: "string_service",
		Name:      "duration_seconds",
	}, []string{})

	svc := StringService{}
	uppercaseEndpoint := instrumentationMiddleware(requestCount, duration)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Circuit breaker middleware for Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/circuitbreaker"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/sony/gobreaker"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	breaker := circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))

	uppercaseEndpoint := breaker(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Using retry middleware with Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/retry"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	retryEndpoint := retry.NewEndpoint(
		makeUppercaseEndpoint(svc),
		retry.RetryOptions{Max: 3, Interval: 5 * time.Second},
	)

	uppercaseHandler := httptransport.NewServer(
		retryEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding custom request context in Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			ctx := context.WithValue(r.Context(), "requestID", "123")
			r = r.WithContext(ctx)
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding error handling middleware to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func errorMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			response, err := next(ctx, request)
			if err != nil {
				logger.Log("error", err)
			}
			return response, err
		}
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := errorMiddleware(logger)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding authentication middleware to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple token-based auth
		token := r.Header.Get("Authorization")
		if token != "valid-token" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", authMiddleware(uppercaseHandler))
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding timeout middleware to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func timeoutMiddleware(next endpoint.Endpoint) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return next(ctx, request)
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := timeoutMiddleware(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Using multiple endpoints in Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	countEndpoint := makeCountEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	countHandler := httptransport.NewServer(
		countEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	http.Handle("/count", countHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding tracing middleware to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	zipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/middleware/http"
	zipkinReporter "github.com/openzipkin/zipkin-go/reporter/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	tracer, _ := zipkin.NewTracer(zipkinReporter.NewReporter("http://localhost:9411/api/v2/spans"))
	uppercaseEndpoint := zipkinHTTP.NewServerMiddleware(tracer)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Custom request/response encoder and decoder in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com.go-kit/kit/transport/http"
)

type request struct {
	S string `json:"s"`
}

type response struct {
	V string `json:"v"`
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var req request
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, err
			}
			return req, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Service discovery with Consul in Go Kit service
package main

import (
	"context"
	"net"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/consul/consulsd"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hashicorp/consul/api"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	consulClient, _ := api.NewClient(api.DefaultConfig())
	client := consulsd.NewClient(consulClient)
	registrar := consulsd.NewRegistrar(client, &consul.Registration{
		ID:      "uppercase",
		Name:    "uppercase",
		Address: "localhost",
		Port:    8080,
	}, logger)

	registrar.Register()
	defer registrar.Deregister()

	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}




// Service discovery with etcd in Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/etcdv3"
	httptransport "github.com/go-kit/kit/transport/http"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
	})

	registrar := etcdv3.NewRegistrar(client, etcdv3.Service{
		Key:   "/services/uppercase",
		Value: "http://localhost:8080",
	}, logger)

	registrar.Register()
	defer registrar.Deregister()

	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding rate limiting middleware to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/ratelimit"
	httptransport "github.com/go-kit/kit/transport/http"
	"golang.org/x/time/rate"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	limiter := rate.NewLimiter(rate.Every(1*time.Second), 1)
	uppercaseEndpoint := ratelimit.NewErroringLimiter(limiter)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding Prometheus metrics to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics/prometheus"
	httptransport "github.com/go-kit/kit/transport/http"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	requestCount := prometheus.NewCounterFrom(stdprometheus.CounterOpts{
		Namespace: "example",
		Subsystem: "string_service",
		Name:      "request_count",
	}, []string{})
	svc := StringService{}
	uppercaseEndpoint := prometheus.NewCounterMiddleware(requestCount)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	http.Handle("/metrics", stdprometheus.Handler())
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding throttling to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/throttle"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	upperEndpoint := throttle.Throttle(1, 1*time.Second)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		upperEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Implementing graceful shutdown in Go Kit service
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	server := &http.Server{Addr: ":8080"}

	go func() {
		logger.Log("msg", "HTTP", "addr", ":8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log("error", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	logger.Log("msg", "Server gracefully stopped")
}




// Dynamic client-side load balancing in Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/consul/consulsd"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hashicorp/consul/api"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	consulClient, _ := api.NewClient(api.DefaultConfig())
	client := consulsd.NewClient(consulClient)

	instancer := consulsd.NewInstancer(client, logger, "uppercase", []string{}, true)
	endpointer := consulsd.NewEndpointer(instancer, makeUppercaseFactory(), logger)
	balancer := lb.NewRoundRobin(endpointer)

	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", httptransport.NewServer(balancer.Endpoint(), nil, nil))
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding Zipkin tracing to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	zipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/middleware/http"
	zipkinReporter "github.com/openzipkin/zipkin-go/reporter/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	tracer, _ := zipkin.NewTracer(zipkinReporter.NewReporter("http://localhost:9411/api/v2/spans"))
	svc := StringService{}
	uppercaseEndpoint := zipkinHTTP.NewServerMiddleware(tracer)(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding a custom HTTP handler in Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerBefore(func(ctx context.Context, r *http.Request) context.Context {
			// Add custom logic before handling request
			return ctx
		}),
		httptransport.ServerAfter(func(ctx context.Context, w http.ResponseWriter) context.Context {
			// Add custom logic after handling request
			return ctx
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding circuit breaker to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/consul/consulsd"
	"github.com/go-kit/kit/circuitbreaker"
	"github.com/sony/gobreaker"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hashicorp/consul/api"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	consulClient, _ := api.NewClient(api.DefaultConfig())
	client := consulsd.NewClient(consulClient)

	instancer := consulsd.NewInstancer(client, logger, "uppercase", []string{}, true)
	endpointer := consulsd.NewEndpointer(instancer, makeUppercaseFactory(), logger)
	breaker := circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))
	balancer := lb.NewRoundRobin(endpointer)

	svc := StringService{}
	uppercaseEndpoint := breaker(makeUppercaseEndpoint(svc))

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", httptransport.NewServer(balancer.Endpoint(), nil, nil))
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding retry with circuit breaker to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/consul/consulsd"
	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/retry"
	"github.com/sony/gobreaker"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hashicorp/consul/api"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	consulClient, _ := api.NewClient(api.DefaultConfig())
	client := consulsd.NewClient(consulClient)

	instancer := consulsd.NewInstancer(client, logger, "uppercase", []string{}, true)
	endpointer := consulsd.NewEndpointer(instancer, makeUppercaseFactory(), logger)
	breaker := circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))
	retryEndpoint := retry.NewEndpoint(breaker(makeUppercaseEndpoint(svc)), retry.RetryOptions{Max: 3, Interval: 5 * time.Second})
	balancer := lb.NewRoundRobin(endpointer)

	svc := StringService{}
	uppercaseEndpoint := retryEndpoint

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", httptransport.NewServer(balancer.Endpoint(), nil, nil))
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding retry with circuit breaker to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/sd/lb"
	"github.com/go-kit/kit/sd/consul"
	"github.com/go-kit/kit/sd/consul/consulsd"
	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/retry"
	"github.com/sony/gobreaker"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/hashicorp/consul/api"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	consulClient, _ := api.NewClient(api.DefaultConfig())
	client := consulsd.NewClient(consulClient)

	instancer := consulsd.NewInstancer(client, logger, "uppercase", []string{}, true)
	endpointer := consulsd.NewEndpointer(instancer, makeUppercaseFactory(), logger)
	breaker := circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))
	retryEndpoint := retry.NewEndpoint(breaker(makeUppercaseEndpoint(svc)), retry.RetryOptions{Max: 3, Interval: 5 * time.Second})
	balancer := lb.NewRoundRobin(endpointer)

	svc := StringService{}
	uppercaseEndpoint := retryEndpoint

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", httptransport.NewServer(balancer.Endpoint(), nil, nil))
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding custom middleware to Go Kit service
package main

import (
	"context"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerBefore(func(ctx context.Context, r *http.Request) context.Context {
			// Custom middleware logic
			return ctx
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Setting up a JSON RPC server with Go Kit
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport/http/jsonrpc"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := jsonrpc.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/rpc/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}




// Adding timeout middleware to Go Kit service
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	uppercaseEndpoint = tracing.ServerMiddleware(log.NewNopLogger())(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerBefore(func(ctx context.Context, r *http.Request) context.Context {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			go func() {
				<-ctx.Done()
				if ctx.Err() == context.DeadlineExceeded {
					cancel()
				}
			}()
			return ctx
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding caching middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type cache struct {
	mu    sync.Mutex
	store map[string]string
}

func (c *cache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	val, ok := c.store[key]
	return val, ok
}

func (c *cache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	c := &cache{store: make(map[string]string)}

	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			req := request.(string)
			if val, ok := c.Get(req); ok {
				return val, nil
			}
			resp, err := next(ctx, req)
			if err == nil {
				c.Set(req, resp.(string))
			}
			return resp, err
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding rate limiting middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/ratelimit"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	limiter := ratelimit.NewTokenBucketLimiter(ratelimit.NewBucketWithRate(1, 1))

	uppercaseEndpoint = limiter(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding request logging middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			logger.Log("msg", "request received")
			defer logger.Log("msg", "request completed")
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding metrics middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"github.com/go-kit/kit/metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	counter := prometheus.NewCounterFrom(prometheus.CounterOpts{
		Namespace: "example",
		Name:      "uppercase_request_count",
		Help:      "Number of requests received for uppercase endpoint",
	}, []string{})

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			counter.Add(1)
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	http.Handle("/metrics", promhttp.Handler())
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}






// Adding timeout and retry middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/retry"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			return retry.Retry(3, time.Second, 2, next)(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			if s == "retry" {
				return nil, errors.New("temporary error, please retry")
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding custom response headers in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			w.Header().Set("X-Custom-Header", "Value")
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}




// Adding request ID middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type contextKey string

const requestIDKey = contextKey("requestID")

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			reqID := ctx.Value(requestIDKey).(string)
			logger.Log("requestID", reqID, "msg", "request received")
			defer logger.Log("requestID", reqID, "msg", "request completed")
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			reqID := r.Header.Get("X-Request-ID")
			ctx = context.WithValue(ctx, requestIDKey, reqID)
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding circuit breaker middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-kit/kit/circuitbreaker"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/sony/gobreaker"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	cb := circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:    "uppercase",
		Timeout: 5 * time.Second,
	}))

	uppercaseEndpoint = cb(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			if s == "break" {
				return nil, errors.New("service unavailable")
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Implementing service discovery in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type Discovery struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	discovery := Discovery{Host: "localhost", Port: "8080"}

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			w.Header().Set("X-Service-Host", discovery.Host)
			w.Header().Set("X-Service-Port", discovery.Port)
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Implementing event-driven communication in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type Event struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	eventBus := make(chan Event)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			eventBus <- Event{Type: "uppercase", Message: s}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	go func() {
		for {
			select {
			case event := <-eventBus:
				logger.Log("event", event.Type, "message", event.Message)
			}
		}
	}()

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Logging with context in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			logger := log.With(logger, "method", "uppercase")
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				logger.Log("error", err)
				return nil, err
			}
			logger.Log("msg", "received", "string", s)
			return s, nil
		},
		func(ctx context.Context, w http.ResponseWriter, response interface{}) error {
			logger := log.With(logger, "method", "uppercase")
			logger.Log("msg", "sending response")
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Implementing graceful shutdown with context in Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(ctx context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)

	go func() {
		logger.Log("msg", "HTTP", "addr", ":8080")
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			logger.Log("msg", "HTTP server stopped")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	logger.Log("msg", "shutting down HTTP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Log("error", err)
	}
}






// Adding timeout middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)
	timeout := 3 * time.Second

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding timeout middleware with default value to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

const defaultTimeout = 3 * time.Second

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			timeout, ok := ctx.Deadline()
			if !ok {
				ctx, _ = context.WithTimeout(ctx, defaultTimeout)
			} else {
				logger.Log("msg", "using request deadline as timeout", "deadline", timeout)
			}
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(_ context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
		httptransport.ServerErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}),
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}







// Adding context value middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

type contextKey string

const userIDKey = contextKey("userID")

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			userID := ctx.Value(userIDKey).(string)
			logger.Log("userID", userID, "msg", "request received")
			defer logger.Log("userID", userID, "msg", "request completed")
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			userID := r.Header.Get("X-User-ID")
			ctx = context.WithValue(ctx, userIDKey, userID)
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}




// Adding request ID middleware with UUID generation to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	uuid "github.com/satori/go.uuid"
)

type contextKey string

const requestIDKey = contextKey("requestID")

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			reqID := ctx.Value(requestIDKey).(string)
			logger.Log("requestID", reqID, "msg", "request received")
			defer logger.Log("requestID", reqID, "msg", "request completed")
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			reqID := uuid.NewV4().String()
			ctx = context.WithValue(ctx, requestIDKey, reqID)
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}





// Adding structured logging middleware to Go Kit service
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
)

func main() {
	logger := log.NewLogfmtLogger(log.StdlibWriter{})
	svc := StringService{}
	uppercaseEndpoint := makeUppercaseEndpoint(svc)

	uppercaseEndpoint = func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			logger.Log("msg", "request received", "request", request)
			defer logger.Log("msg", "request completed")
			return next(ctx, request)
		}
	}(uppercaseEndpoint)

	uppercaseHandler := httptransport.NewServer(
		uppercaseEndpoint,
		func(ctx context.Context, r *http.Request) (interface{}, error) {
			var s string
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				return nil, err
			}
			return s, nil
		},
		func(_ context.Context, w http.ResponseWriter, response interface{}) error {
			logger.Log("msg", "sending response", "response", response)
			return json.NewEncoder(w).Encode(response)
		},
	)

	http.Handle("/uppercase", uppercaseHandler)
	logger.Log("msg", "HTTP", "addr", ":8080")
	http.ListenAndServe(":8080", nil)
}









// Example 1: Sending a basic email using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Hello from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent using go-mail library.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email: %v", err)
    }
    log.Println("Email sent successfully!")
}





// Example 2: Sending an email with HTML content using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("HTML Email from Go-Mail")
    email.SetBody(mail.TextHTML, "<html><body><h1>Hello</h1><p>This is a <b>test</b> email.</p></body></html>")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email: %v", err)
    }
    log.Println("HTML Email sent successfully!")
}





// Example 3: Sending an email with attachments using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Attachment from Go-Mail")
    email.SetBody(mail.TextPlain, "This email contains an attachment.")

    // Attach a file
    file, err := os.Open("attachment.pdf")
    if err != nil {
        log.Fatalf("Error opening attachment: %v", err)
    }
    defer file.Close()

    email.Attach(file, "attachment.pdf")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with attachment: %v", err)
    }
    log.Println("Email with attachment sent successfully!")
}





// Example 4: Sending an email with inline images using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Inline Image from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><body><h1>Hello</h1><p>This is an email with an inline image: <img src="cid:image1"></p></body></html>`)

    // Attach inline image
    file, err := os.Open("image.jpg")
    if err != nil {
        log.Fatalf("Error opening image: %v", err)
    }
    defer file.Close()

    email.Attach(file, "image.jpg", mail.InlineFile("image1"))

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with inline image: %v", err)
    }
    log.Println("Email with inline image sent successfully!")
}





// Example 5: Sending an email using TLS encryption with go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client with TLS
    smtp := mail.NewSMTPWithTLS("smtp.example.com", 587, "username", "password", nil)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("TLS Encrypted Email from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent using TLS encryption.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending TLS encrypted email: %v", err)
    }
    log.Println("TLS encrypted email sent successfully!")
}





// Example 6: Sending an email using SSL with go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client with SSL
    smtp := mail.NewSMTPWithSSL("smtp.example.com", 465, "username", "password", nil)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("SSL Encrypted Email from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent using SSL encryption.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending SSL encrypted email: %v", err)
    }
    log.Println("SSL encrypted email sent successfully!")
}





// Example 7: Sending an email with custom headers using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with custom headers
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Custom Headers from Go-Mail")
    email.SetBody(mail.TextPlain, "This email includes custom headers.")
    email.AddHeader("X-Custom-Header", "Custom Value")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom headers: %v", err)
    }
    log.Println("Email with custom headers sent successfully!")
}





// Example 8: Sending an email using a template with go-mail library.

package main

import (
    "html/template"
    "log"
    "bytes"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Define email template
    const emailTemplate = `
        <html>
        <body>
            <h1>Hello, {{.Name}}!</h1>
            <p>This is a test email.</p>
        </body>
        </html>`

    // Prepare data for template
    data := struct {
        Name string
    }{
        Name: "John Doe",
    }

    // Render template
    tmpl := template.Must(template.New("emailTemplate").Parse(emailTemplate))
    var tpl bytes.Buffer
    err := tmpl.Execute(&tpl, data)
    if err != nil {
        log.Fatalf("Error executing template: %v", err)
    }

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Template from Go-Mail")
    email.SetBody(mail.TextHTML, tpl.String())

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with template: %v", err)
    }
    log.Println("Email with template sent successfully!")
}





// Example 9: Sending an email to multiple recipients using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient1@example.com", "recipient2@example.com")
    email.SetSubject("Email to Multiple Recipients from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent to multiple recipients.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email to multiple recipients: %v", err)
    }
    log.Println("Email sent to multiple recipients successfully!")
}





// Example 10: Sending an email with CC and BCC recipients using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.AddCC("cc1@example.com", "cc2@example.com")
    email.AddBCC("bcc1@example.com", "bcc2@example.com")
    email.SetSubject("Email with CC and BCC from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with CC and BCC.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with CC and BCC: %v", err)
    }
    log.Println("Email with CC and BCC sent successfully!")
}





// Example 11: Handling errors when sending an email using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Handling Errors Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email demonstrating error handling.")

    // Send email with error handling
    err := smtp.Send(email)
    if err != nil {
        log.Fatalf("Error sending email: %v", err)
    }
    log.Println("Email sent successfully!")
}





// Example 12: Sending an email with custom SMTP server configuration using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Custom SMTP server configuration
    smtpConfig := mail.SMTPConfig{
        Host:     "smtp.example.com",
        Port:     587,
        Username: "username",
        Password: "password",
        TLSConfig: &mail.TLSConfig{
            InsecureSkipVerify: true, // Example: Insecure skip verify; use carefully in production.
        },
    }

    // Initialize SMTP client with custom configuration
    smtp := mail.NewCustomSMTP(smtpConfig)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom SMTP Configuration Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with custom SMTP configuration.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom SMTP configuration: %v", err)
    }
    log.Println("Email sent with custom SMTP configuration successfully!")
}





// Example 13: Sending an email using OAuth2 authentication with go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // OAuth2 authentication configuration
    oauth2Config := &mail.OAuth2Config{
        Email:      "sender@example.com",
        ClientID:   "your_client_id",
        ClientSecret: "your_client_secret",
        AccessToken: "access_token",
        RefreshToken: "refresh_token",
    }

    // Initialize SMTP client with OAuth2 authentication
    smtp := mail.NewSMTPWithOAuth2("smtp.example.com", 587, oauth2Config)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("OAuth2 Authentication Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent using OAuth2 authentication.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with OAuth2 authentication: %v", err)
    }
    log.Println("Email sent using OAuth2 authentication successfully!")
}





// Example 14: Sending an email with embedded images using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Embedded Image from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><body><h1>Hello</h1><p>This email includes an embedded image: <img src="cid:image1"></p></body></html>`)

    // Attach embedded image
    file, err := os.Open("image.jpg")
    if err != nil {
        log.Fatalf("Error opening image: %v", err)
    }
    defer file.Close()

    email.Attach(file, "image.jpg", mail.InlineFile("image1"))

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with embedded image: %v", err)
    }
    log.Println("Email with embedded image sent successfully!")
}





// Example 15: Sending an email with alternative text (plaintext and HTML) using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with alternative text (plaintext and HTML)
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Alternative Text from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with alternative plain text.")
    email.AddAlternative(mail.TextHTML, "<html><body><h1>Hello</h1><p>This is a test email with alternative HTML.</p></body></html>")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with alternative text: %v", err)
    }
    log.Println("Email with alternative text sent successfully!")
}





// Example 16: Sending an email with retry mechanism using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Retry Mechanism Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with retry mechanism.")

    // Send email with retry
    var err error
    for attempt := 1; attempt <= 3; attempt++ {
        if err = smtp.Send(email); err == nil {
            log.Println("Email sent successfully!")
            break
        }
        log.Printf("Error sending email (attempt %d): %v", attempt, err)
        time.Sleep(5 * time.Second) // Wait before retrying
    }
    if err != nil {
        log.Fatalf("Failed to send email after 3 attempts: %v", err)
    }
}





// Example 17: Sending an email with custom headers and attachments using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with custom headers and attachments
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Custom Headers and Attachments from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with custom headers and attachments.")
    email.AddHeader("X-Custom-Header", "Custom Value")

    // Attach a file
    file, err := os.Open("attachment.pdf")
    if err != nil {
        log.Fatalf("Error opening attachment: %v", err)
    }
    defer file.Close()

    email.Attach(file, "attachment.pdf")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom headers and attachments: %v", err)
    }
    log.Println("Email with custom headers and attachments sent successfully!")
}





// Example 18: Sending an email with multiple attachments using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with multiple attachments
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Multiple Attachments from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with multiple attachments.")

    // Attach multiple files
    files := []string{"attachment1.pdf", "attachment2.docx"}
    for _, filename := range files {
        file, err := os.Open(filename)
        if err != nil {
            log.Printf("Error opening attachment %s: %v", filename, err)
            continue
        }
        defer file.Close()
        email.Attach(file, filename)
    }

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with multiple attachments: %v", err)
    }
    log.Println("Email with multiple attachments sent successfully!")
}





// Example 19: Sending an email with dynamic recipients from a list using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Dynamic recipients list
    recipients := []string{"recipient1@example.com", "recipient2@example.com", "recipient3@example.com"}

    // Send emails to each recipient
    for _, recipient := range recipients {
        // Compose email
        email := mail.NewMessage()
        email.SetFrom("sender@example.com")
        email.AddTo(recipient)
        email.SetSubject("Dynamic Recipients Example from Go-Mail")
        email.SetBody(mail.TextPlain, "This is a test email sent to dynamic recipients.")

        // Send email
        if err := smtp.Send(email); err != nil {
            log.Printf("Error sending email to %s: %v", recipient, err)
            continue
        }
        log.Printf("Email sent to %s successfully!", recipient)
    }
}





// Example 20: Sending an email with custom sender name and reply-to address using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with custom sender name and reply-to address
    email := mail.NewMessage()
    email.SetFromWithAlias("sender@example.com", "Sender Name")
    email.AddTo("recipient@example.com")
    email.SetReplyTo("replyto@example.com")
    email.SetSubject("Email with Custom Sender and Reply-To from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with custom sender and reply-to.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom sender and reply-to: %v", err)
    }
    log.Println("Email with custom sender and reply-to sent successfully!")
}





// Example 21: Sending an email with UTF-8 content using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")
    smtp.SetCharset("UTF-8") // Set UTF-8 encoding

    // Compose email with UTF-8 content
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("UTF-8 Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with UTF-8 content: 你好, Hello, ¡Hola!")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending UTF-8 email: %v", err)
    }
    log.Println("UTF-8 email sent successfully!")
}





// Example 22: Sending an email with inline CSS using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with inline CSS
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Inline CSS Example from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><head><style>body { font-family: Arial, sans-serif; }</style></head><body><h1>Hello</h1><p style="color: blue;">This is a test email with inline CSS.</p></body></html>`)

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with inline CSS: %v", err)
    }
    log.Println("Email with inline CSS sent successfully!")
}





// Example 23: Sending an email with dynamic content using go-mail library.

package main

import (
    "log"
    "fmt"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Dynamic content
    recipient := "recipient@example.com"
    subject := "Dynamic Content Email Example from Go-Mail"
    message := "This is a test email with dynamic content."

    // Compose email with dynamic content
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo(recipient)
    email.SetSubject(subject)
    email.SetBody(mail.TextPlain, message)

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with dynamic content: %v", err)
    }
    log.Println("Email with dynamic content sent successfully!")
}





// Example 24: Sending an email using an HTML template with go-mail library.

package main

import (
    "log"
    "html/template"
    "bytes"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Define HTML email template
    const emailTemplate = `
        <html>
        <body>
            <h1>Hello, {{.Name}}!</h1>
            <p>This is a test email sent using an HTML template.</p>
        </body>
        </html>`

    // Prepare data for template
    data := struct {
        Name string
    }{
        Name: "John Doe",
    }

    // Render template
    tpl := template.Must(template.New("emailTemplate").Parse(emailTemplate))
    var tplBuffer bytes.Buffer
    if err := tpl.Execute(&tplBuffer, data); err != nil {
        log.Fatalf("Error executing template: %v", err)
    }

    // Compose email with HTML template
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("HTML Template Email Example from Go-Mail")
    email.SetBody(mail.TextHTML, tplBuffer.String())

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with HTML template: %v", err)
    }
    log.Println("Email with HTML template sent successfully!")
}





// Example 25: Sending an email with scheduled delivery using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Schedule email delivery for 1 minute later
    deliveryTime := time.Now().Add(1 * time.Minute)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Scheduled Delivery Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with scheduled delivery.")

    // Schedule delivery
    if err := smtp.Schedule(email, deliveryTime); err != nil {
        log.Fatalf("Error scheduling email delivery: %v", err)
    }
    log.Printf("Email scheduled for delivery at %s", deliveryTime.Format(time.RFC3339))
}





// Example 26: Sending an email with high priority using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with high priority
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("High Priority Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with high priority.")
    email.SetPriority(mail.PriorityHigh)

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending high priority email: %v", err)
    }
    log.Println("High priority email sent successfully!")
}





// Example 27: Sending an email with custom SMTP timeout using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Custom SMTP configuration with timeout
    smtpConfig := mail.SMTPConfig{
        Host:     "smtp.example.com",
        Port:     587,
        Username: "username",
        Password: "password",
        Timeout:  30 * time.Second, // Custom timeout
    }

    // Initialize SMTP client with custom configuration
    smtp := mail.NewCustomSMTP(smtpConfig)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Timeout Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with custom SMTP timeout.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom timeout: %v", err)
    }
    log.Println("Email sent with custom timeout successfully!")
}





// Example 28: Sending an email with HTML content and attachments using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with HTML content and attachments
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("HTML Email with Attachments Example from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><body><h1>Hello</h1><p>This is a test email with HTML content and attachments.</p></body></html>`)

    // Attach a file
    file, err := os.Open("attachment.pdf")
    if err != nil {
        log.Fatalf("Error opening attachment: %v", err)
    }
    defer file.Close()

    email.Attach(file, "attachment.pdf")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with HTML content and attachments: %v", err)
    }
    log.Println("Email with HTML content and attachments sent successfully!")
}





// Example 29: Sending an email with read receipt request using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with read receipt request
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Read Receipt Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with read receipt request.")
    email.SetReadReceipt("readreceipt@example.com")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with read receipt request: %v", err)
    }
    log.Println("Email with read receipt request sent successfully!")
}





// Example 30: Sending an email with custom SMTP headers using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with custom SMTP headers
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Headers Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with custom SMTP headers.")
    email.AddHeader("X-Custom-Header", "Custom Value")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom headers: %v", err)
    }
    log.Println("Email with custom headers sent successfully!")
}





// Example 31: Sending an email using an HTML template with inline CSS using go-mail library.

package main

import (
    "log"
    "html/template"
    "bytes"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Define HTML email template with inline CSS
    const emailTemplate = `
        <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    color: #333333;
                }
                h1 {
                    color: #0099ff;
                }
            </style>
        </head>
        <body>
            <h1>Hello, {{.Name}}!</h1>
            <p>This is a test email sent using an HTML template with inline CSS.</p>
        </body>
        </html>`

    // Prepare data for template
    data := struct {
        Name string
    }{
        Name: "Jane Doe",
    }

    // Render template
    tpl := template.Must(template.New("emailTemplate").Parse(emailTemplate))
    var tplBuffer bytes.Buffer
    if err := tpl.Execute(&tplBuffer, data); err != nil {
        log.Fatalf("Error executing template: %v", err)
    }

    // Compose email with HTML template and inline CSS
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("HTML Template with Inline CSS Email Example from Go-Mail")
    email.SetBody(mail.TextHTML, tplBuffer.String())

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with HTML template and inline CSS: %v", err)
    }
    log.Println("Email with HTML template and inline CSS sent successfully!")
}





// Example 32: Sending an email to multiple recipients using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Multiple recipients
    recipients := []string{"recipient1@example.com", "recipient2@example.com", "recipient3@example.com"}

    // Compose email for each recipient
    for _, recipient := range recipients {
        email := mail.NewMessage()
        email.SetFrom("sender@example.com")
        email.AddTo(recipient)
        email.SetSubject("Multiple Recipients Email Example from Go-Mail")
        email.SetBody(mail.TextPlain, "This is a test email sent to multiple recipients.")

        // Send email
        if err := smtp.Send(email); err != nil {
            log.Printf("Error sending email to %s: %v", recipient, err)
            continue
        }
        log.Printf("Email sent to %s successfully!", recipient)
    }
}





// Example 33: Sending an email with different encodings using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")
    smtp.SetCharset("ISO-8859-1") // Set encoding to ISO-8859-1 (Latin-1)

    // Compose email with different encoding
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Different Encoding Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with different encoding: café")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with different encoding: %v", err)
    }
    log.Println("Email with different encoding sent successfully!")
}





// Example 34: Sending an email with delayed delivery using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Schedule email delivery after 5 minutes
    deliveryTime := time.Now().Add(5 * time.Minute)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Delayed Delivery Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with delayed delivery.")

    // Schedule delivery
    if err := smtp.Schedule(email, deliveryTime); err != nil {
        log.Fatalf("Error scheduling email delivery: %v", err)
    }
    log.Printf("Email scheduled for delivery at %s", deliveryTime.Format(time.RFC3339))
}





// Example 35: Sending an email with a custom SMTP client using go-mail library.

package main

import (
    "log"
    "net/smtp"

    "github.com/go-mail/mail"
)

func main() {
    // Custom SMTP client configuration
    smtpClient := smtp.NewClient(nil, "smtp.example.com")
    if err := smtpClient.Auth(smtp.PlainAuth("", "username", "password", "smtp.example.com")); err != nil {
        log.Fatalf("Error authenticating SMTP client: %v", err)
    }

    // Initialize custom SMTP client
    smtp := mail.NewCustomSMTPClient(smtpClient)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom SMTP Client Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with a custom SMTP client.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom SMTP client: %v", err)
    }
    log.Println("Email sent with custom SMTP client successfully!")
}





// Example 36: Sending an email using secure SMTP (TLS/SSL) with go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Secure SMTP configuration (using TLS)
    smtpConfig := mail.SMTPConfig{
        Host:     "smtp.example.com",
        Port:     587,
        Username: "username",
        Password: "password",
        TLSConfig: &mail.TLSConfig{
            InsecureSkipVerify: true, // Example: Insecure skip verify; use carefully in production.
        },
    }

    // Initialize secure SMTP client
    smtp := mail.NewCustomSMTP(smtpConfig)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Secure SMTP Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent using secure SMTP (TLS).")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with secure SMTP: %v", err)
    }
    log.Println("Email sent using secure SMTP successfully!")
}





// Example 37: Sending an email with CC and BCC using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with CC and BCC
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.AddCC("cc1@example.com")
    email.AddCC("cc2@example.com")
    email.AddBCC("bcc1@example.com")
    email.AddBCC("bcc2@example.com")
    email.SetSubject("CC and BCC Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with CC and BCC recipients.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with CC and BCC: %v", err)
    }
    log.Println("Email with CC and BCC sent successfully!")
}





// Example 38: Sending an email with a custom Message-ID using go-mail library.

package main

import (
    "log"
    "github.com/go-mail/mail"
    "fmt"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with custom Message-ID
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Message-ID Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with a custom Message-ID.")

    // Set custom Message-ID
    customMessageID := fmt.Sprintf("<custom-%d@example.com>", time.Now().UnixNano())
    email.SetMessageID(customMessageID)

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom Message-ID: %v", err)
    }
    log.Println("Email with custom Message-ID sent successfully!")
}





// Example 39: Sending an email with retry mechanism using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Retry Mechanism Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with retry mechanism.")

    // Retry sending email up to 3 times with exponential backoff
    retryCount := 3
    for i := 0; i < retryCount; i++ {
        if err := smtp.Send(email); err != nil {
            log.Printf("Error sending email (attempt %d): %v", i+1, err)
            // Exponential backoff before retrying
            time.Sleep(time.Duration(i*2) * time.Second)
            continue
        }
        log.Println("Email sent successfully!")
        break
    }
}





// Example 40: Sending an email with HTML content and embedded images using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with HTML content and embedded images
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("HTML Email with Embedded Images Example from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><body><h1>Hello</h1><p>This is a test email with HTML content and embedded image:<br/><img src="cid:logo"></p></body></html>`)

    // Attach embedded image
    imgFile, err := os.Open("logo.png")
    if err != nil {
        log.Fatalf("Error opening image file: %v", err)
    }
    defer imgFile.Close()

    email.Attach(imgFile, "logo.png", mail.InlineFile("logo"))

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with embedded images: %v", err)
    }
    log.Println("Email with HTML content and embedded images sent successfully!")
}





// Example 41: Sending an email with low priority using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with low priority
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Low Priority Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with low priority.")
    email.SetPriority(mail.PriorityLow)

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending low priority email: %v", err)
    }
    log.Println("Low priority email sent successfully!")
}





// Example 42: Sending an email with a Reply-To address using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with Reply-To address
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Reply-To Address Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with a Reply-To address.")
    email.SetReplyTo("reply-to@example.com")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with Reply-To address: %v", err)
    }
    log.Println("Email with Reply-To address sent successfully!")
}





// Example 43: Sending an email with a persistent SMTP connection using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client with persistent connection
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")
    smtp.SetKeepAlive(30 * time.Second) // Keep the connection alive for 30 seconds

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Persistent Connection Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with a persistent SMTP connection.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with persistent connection: %v", err)
    }
    log.Println("Email sent with persistent connection successfully!")
}





// Example 44: Sending an email with a custom retry strategy using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Custom retry strategy
    retryAttempts := 5
    retryInterval := 5 * time.Second

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Retry Strategy Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with a custom retry strategy.")

    // Retry sending email
    for i := 1; i <= retryAttempts; i++ {
        if err := smtp.Send(email); err != nil {
            log.Printf("Attempt %d failed: %v", i, err)
            time.Sleep(retryInterval)
            continue
        }
        log.Println("Email sent successfully!")
        break
    }
}





// Example 45: Sending an email with custom SMTP timeout using go-mail library.

package main

import (
    "log"
    "time"

    "github.com/go-mail/mail"
)

func main() {
    // Custom SMTP configuration with timeout
    smtpConfig := mail.SMTPConfig{
        Host:     "smtp.example.com",
        Port:     587,
        Username: "username",
        Password: "password",
        Timeout:  30 * time.Second, // Custom timeout
    }

    // Initialize SMTP client with custom configuration
    smtp := mail.NewCustomSMTP(smtpConfig)

    // Compose email
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Timeout Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email sent with custom SMTP timeout.")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom timeout: %v", err)
    }
    log.Println("Email sent with custom timeout successfully!")
}





// Example 46: Sending an email with an attachment from a file using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with attachment from file
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Attachment Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with an attachment.")

    // Attach a file
    file, err := os.Open("document.pdf")
    if err != nil {
        log.Fatalf("Error opening attachment file: %v", err)
    }
    defer file.Close()

    email.Attach(file, "document.pdf")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with attachment: %v", err)
    }
    log.Println("Email with attachment sent successfully!")
}





// Example 47: Sending an email with a custom header and UTF-8 encoding using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")
    smtp.SetCharset("UTF-8") // Set encoding to UTF-8

    // Compose email with custom header and UTF-8 encoding
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Custom Header and UTF-8 Encoding Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with custom header and UTF-8 encoding.")
    email.AddHeader("X-Custom-Header", "Custom Value")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with custom header and UTF-8 encoding: %v", err)
    }
    log.Println("Email with custom header and UTF-8 encoding sent successfully!")
}





// Example 48: Sending an email with inline content (inline attachments) using go-mail library.

package main

import (
    "log"
    "os"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with inline content
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Inline Content Email Example from Go-Mail")
    email.SetBody(mail.TextHTML, `<html><body><h1>Hello</h1><p>This is a test email with inline image: <img src="cid:image1"></p></body></html>`)

    // Attach inline content (image)
    imgFile, err := os.Open("image.jpg")
    if err != nil {
        log.Fatalf("Error opening image file: %v", err)
    }
    defer imgFile.Close()

    email.Attach(imgFile, "image.jpg", mail.InlineFile("image1"))

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with inline content: %v", err)
    }
    log.Println("Email with inline content sent successfully!")
}





// Example 49: Sending an email with delivery status notification (DSN) using go-mail library.

package main

import (
    "log"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Compose email with delivery status notification (DSN)
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("DSN Email Example from Go-Mail")
    email.SetBody(mail.TextPlain, "This is a test email with delivery status notification (DSN).")
    email.SetDSN("never")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with delivery status notification (DSN): %v", err)
    }
    log.Println("Email with delivery status notification (DSN) sent successfully!")
}





// Example 50: Sending an email with template data loaded from a JSON file using go-mail library.

package main

import (
    "log"
    "io/ioutil"
    "encoding/json"

    "github.com/go-mail/mail"
)

func main() {
    // Initialize SMTP client
    smtp := mail.NewSMTP("smtp.example.com", 587, "username", "password")

    // Load template data from JSON file
    templateData, err := ioutil.ReadFile("email_data.json")
    if err != nil {
        log.Fatalf("Error reading template data from JSON file: %v", err)
    }

    // Unmarshal JSON data
    var data map[string]interface{}
    if err := json.Unmarshal(templateData, &data); err != nil {
        log.Fatalf("Error unmarshaling JSON data: %v", err)
    }

    // Compose email with template data
    email := mail.NewMessage()
    email.SetFrom("sender@example.com")
    email.AddTo("recipient@example.com")
    email.SetSubject("Email with Template Data Example from Go-Mail")

    // Example assumes email_data.json contains key "name" with value "John Doe"
    email.SetBody(mail.TextPlain, "Hello, "+data["name"].(string)+"!")

    // Send email
    if err := smtp.Send(email); err != nil {
        log.Fatalf("Error sending email with template data: %v", err)
    }
    log.Println("Email with template data sent successfully!")
}










// Basic Routing with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router instance
	r := mux.NewRouter()

	// Define a handler function
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux!")
	}

	// Register the handler function for the "/" route
	r.HandleFunc("/", handler)

	// Start the HTTP server
	http.ListenAndServe(":8080", r)
}





// Handling Route Parameters with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router instance
	r := mux.NewRouter()

	// Define a handler function for "/hello/{name}"
	handler := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		name := vars["name"]
		fmt.Fprintf(w, "Hello, %s!", name)
	}

	// Register the handler function for the "/hello/{name}" route
	r.HandleFunc("/hello/{name}", handler)

	// Start the HTTP server
	http.ListenAndServe(":8080", r)
}





// Example 1: Serving Static Files with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Serve static files from the "static" directory
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.ListenAndServe(":8080", r)
}





// Example 2: Using Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing middleware...")
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply middleware to all routes
	r.Use(middleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Middleware!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 3: Using Subrouters with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Subrouter for API routes
	api := r.PathPrefix("/api").Subrouter()

	api.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint: List of Users")
	})

	api.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint: List of Products")
	})

	http.ListenAndServe(":8080", r)
}





// Example 4: Handling Query Parameters with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		searchTerm := queryParams.Get("q")
		fmt.Fprintf(w, "Search Query: %s", searchTerm)
	})

	http.ListenAndServe(":8080", r)
}





// Example 5: Using Route Constraints with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/user/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		fmt.Fprintf(w, "User ID: %s", id)
	})

	http.ListenAndServe(":8080", r)
}





// Example 6: Custom 404 Handler with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Custom 404 handler
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Custom 404 Not Found")
	})

	http.ListenAndServe(":8080", r)
}





// Example 7: Named Routes with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/articles/{category}/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		category := vars["category"]
		id := vars["id"]
		fmt.Fprintf(w, "Category: %s, ID: %s", category, id)
	}).Methods("GET").Name("articleRoute")

	// Generating a URL using the named route
	url, err := r.Get("articleRoute").URL("category", "technology", "id", "42")
	if err == nil {
		fmt.Println("Generated URL:", url.String())
	}

	http.ListenAndServe(":8080", r)
}





// Example 8: Route Prefixes with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Subrouter for all routes prefixed with "/admin"
	admin := r.PathPrefix("/admin").Subrouter()

	admin.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Admin Dashboard")
	})

	admin.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Admin Settings")
	})

	http.ListenAndServe(":8080", r)
}





// Example 9: Custom Middleware for Logging with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		fmt.Printf("[%s] %s %s\n", r.Method, r.RequestURI, time.Since(start))
	})
}

func main() {
	r := mux.NewRouter()

	// Apply logging middleware
	r.Use(loggingMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Logging Middleware!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 10: Route Middleware for Authentication with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate authentication check (e.g., JWT verification)
		token := r.Header.Get("Authorization")
		if token != "valid_token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply authentication middleware to specific route
	r.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Authenticated Route")
	}).Methods("GET").Name("protectedRoute").Middleware(authMiddleware)

	http.ListenAndServe(":8080", r)
}





// Example 11: Custom Error Handling with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func errorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Custom Error Message", http.StatusInternalServerError)
}

func main() {
	r := mux.NewRouter()

	// Register a handler for an error endpoint
	r.HandleFunc("/error", errorHandler)

	http.ListenAndServe(":8080", r)
}





// Example 12: Route Groups with Middleware using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Logging Middleware: ", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Group of routes with shared middleware
	api := r.PathPrefix("/api").Subrouter()
	api.Use(loggingMiddleware)

	api.HandleFunc("/endpoint1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint 1")
	})

	api.HandleFunc("/endpoint2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint 2")
	})

	http.ListenAndServe(":8080", r)
}





// Example 13: Handling HTTP Methods with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Route with specific HTTP method
	r.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprintf(w, "Form Submitted via POST")
		} else {
			fmt.Fprintf(w, "Method not allowed")
		}
	}).Methods(http.MethodGet, http.MethodPost)

	http.ListenAndServe(":8080", r)
}





// Example 14: Serving Single Page Applications (SPA) with Gorilla Mux

package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Serve SPA from the "build" directory
	spa := http.FileServer(http.Dir("build"))
	r.PathPrefix("/").Handler(spa)

	// Handle 404 errors by serving the SPA
	r.NotFoundHandler = spa

	http.ListenAndServe(":8080", r)
}





// Example 15: Custom Middleware for Structured Logging with Gorilla Mux

package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Pass request to the next handler
		next.ServeHTTP(w, r)

		// Log request details
		log.Printf("[%s] %s %s %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	})
}

func main() {
	r := mux.NewRouter()

	// Apply logging middleware to all routes
	r.Use(loggingMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Gorilla Mux with Structured Logging!"))
	})

	http.ListenAndServe(":8080", r)
}





// Example 16: URL Path Prefix and Stripping with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Define a route with a path prefix
	r.HandleFunc("/files/{filepath:.+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		filepath := vars["filepath"]
		fmt.Fprintf(w, "File Path: %s", filepath)
	}).Methods("GET")

	// Serve static files from the "files" directory
	r.PathPrefix("/files/").Handler(http.StripPrefix("/files/", http.FileServer(http.Dir("files"))))

	http.ListenAndServe(":8080", r)
}





// Example 17: Middleware Chain with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func middleware1(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing middleware 1...")
		next.ServeHTTP(w, r)
	})
}

func middleware2(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing middleware 2...")
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Chain multiple middlewares
	r.Use(middleware1)
	r.Use(middleware2)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Middleware Chain!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 18: Subrouter with Middleware Chain using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Logging Middleware: ", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate authentication check
		token := r.Header.Get("Authorization")
		if token != "valid_token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Subrouter with middleware chain
	api := r.PathPrefix("/api").Subrouter()
	api.Use(loggingMiddleware)
	api.Use(authMiddleware)

	api.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Accessed Protected Resource")
	})

	http.ListenAndServe(":8080", r)
}





// Example 19: Custom Middleware for CORS with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow CORS from any origin with certain headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply CORS middleware
	r.Use(corsMiddleware)

	r.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Data endpoint with CORS enabled"))
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 20: Middleware to Set Response Headers with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func setHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set custom response headers
		w.Header().Set("X-Server-Version", "1.0")
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply headers middleware
	r.Use(setHeadersMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Custom Headers!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 21: Custom Error Handling with Logging using Gorilla Mux

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func errorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Custom Error Message", http.StatusInternalServerError)
	log.Printf("Error: %s %s", r.Method, r.URL.Path)
}

func main() {
	r := mux.NewRouter()

	// Register a handler for an error endpoint
	r.HandleFunc("/error", errorHandler)

	http.ListenAndServe(":8080", r)
}





// Example 22: Route Prefix with Authentication using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate authentication check
		token := r.Header.Get("Authorization")
		if token != "valid_token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Protected routes under "/secure" path
	secure := r.PathPrefix("/secure").Subrouter()
	secure.Use(authMiddleware)

	secure.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Accessed Protected Profile")
	})

	secure.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Accessed Protected Settings")
	})

	http.ListenAndServe(":8080", r)
}





// Example 23: URL Path with Regular Expressions using Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Route with regular expression path constraint
	r.HandleFunc("/product/{category:[a-z]+}/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		category := vars["category"]
		id := vars["id"]
		fmt.Fprintf(w, "Category: %s, ID: %s", category, id)
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 24: Request Logging with Context using Gorilla Mux

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Pass request to the next handler
		next.ServeHTTP(w, r)

		log.Printf("Completed %s in %v", r.URL.Path, time.Since(start))
	})
}

func main() {
	r := mux.NewRouter()

	// Apply logging middleware to all routes
	r.Use(loggingMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Request Logging!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 25: Handling JSON Requests and Responses with Gorilla Mux

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	r := mux.NewRouter()

	// JSON response example
	r.HandleFunc("/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		userID := vars["id"]

		// Simulate fetching user data from a database
		user := User{
			ID:       1,
			Username: "john_doe",
			Email:    "john.doe@example.com",
		}

		// Convert user struct to JSON
		jsonData, err := json.Marshal(user)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Set content type header and write JSON response
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 26: Route Variables and Path Encoding with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Route with URL variables and path encoding
	r.HandleFunc("/article/{title}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		title := vars["title"]
		fmt.Fprintf(w, "Article Title: %s", title)
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 27: Request Logging with Response Time using Gorilla Mux

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Pass request to the next handler
		next.ServeHTTP(w, r)

		log.Printf("Completed %s in %v", r.URL.Path, time.Since(start))
	})
}

func main() {
	r := mux.NewRouter()

	// Apply logging middleware to all routes
	r.Use(loggingMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Request Logging and Response Time!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 28: Handling Form Data with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Handle form submission
	r.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		fmt.Fprintf(w, "Submitted Form Data: Username - %s, Password - %s", username, password)
	}).Methods("POST")

	http.ListenAndServe(":8080", r)
}






// Example 29: IP Filtering Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/mux"
)

func ipFilterMiddleware(next http.Handler) http.Handler {
	allowedIPs := []string{"127.0.0.1", "::1"} // Allowed IPs

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if IP is in the allowed list
		allowed := false
		for _, allowedIP := range allowedIPs {
			if ip == allowedIP {
				allowed = true
				break
			}
		}

		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply IP filtering middleware to all routes
	r.Use(ipFilterMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with IP Filtering Middleware!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 30: Handling File Uploads with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB limit
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get file from form data
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a new file on the server
	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Copy file content from uploaded file to the new file
	_, err = io.Copy(f, file)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File uploaded successfully: %s", handler.Filename)
}

func main() {
	r := mux.NewRouter()

	// Handle file upload
	r.HandleFunc("/upload", uploadFileHandler).Methods("POST")

	http.ListenAndServe(":8080", r)
}





// Example 31: URL Path with Query Parameters using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Route with URL path and query parameters
	r.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		searchTerm := queryParams.Get("q")
		fmt.Fprintf(w, "Search Query: %s", searchTerm)
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 32: Subrouter with Custom Middleware using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Logging Middleware: ", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Subrouter with custom middleware
	api := r.PathPrefix("/api").Subrouter()
	api.Use(loggingMiddleware)

	api.HandleFunc("/endpoint1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint 1")
	})

	api.HandleFunc("/endpoint2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API Endpoint 2")
	})

	http.ListenAndServe(":8080", r)
}





// Example 33: Route with Custom Handler Function using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func customHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Custom Handler Function")
}

func main() {
	r := mux.NewRouter()

	// Route with a custom handler function
	r.HandleFunc("/custom", customHandler)

	http.ListenAndServe(":8080", r)
}





// Example 34: Rate Limiting Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

func rateLimitMiddleware(next http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Every(time.Second), 10) // 10 requests per second

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Rate Limit Exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply rate limiting middleware to all routes
	r.Use(rateLimitMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Rate Limiting Middleware!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 35: CSRF Protection Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// CSRF protection middleware
	csrfMiddleware := csrf.Protect([]byte("32-byte-long-auth-key"))

	// Apply CSRF middleware to all routes
	r.Use(csrfMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Generate CSRF token
		token := csrf.Token(r)
		fmt.Fprintf(w, "CSRF Token: %s", token)
	})

	http.ListenAndServe(":8080", r)
}





// Example 36: Route with Custom Response Headers using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func customHeadersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Custom-Header", "Value")
	fmt.Fprintf(w, "Response with Custom Headers")
}

func main() {
	r := mux.NewRouter()

	// Route with custom response headers
	r.HandleFunc("/custom-headers", customHeadersHandler)

	http.ListenAndServe(":8080", r)
}





// Example 37: Authentication Middleware with JWT using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var jwtKey = []byte("secret_key")

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate JWT token validation
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check token signing method etc.
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply authentication middleware to specific route
	r.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Authenticated Route")
	}).Methods("GET").Name("protectedRoute").Middleware(authMiddleware)

	http.ListenAndServe(":8080", r)
}





// Example 38: Handling Multiple Parameters in URL Path using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Route with multiple parameters in URL path
	r.HandleFunc("/product/{category}/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		category := vars["category"]
		id := vars["id"]
		fmt.Fprintf(w, "Category: %s, ID: %s", category, id)
	}).Methods("GET")

	http.ListenAndServe(":8080", r)
}





// Example 39: Serving Gzip Compressed Content with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Serve gzip compressed content
	r.HandleFunc("/compressed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		http.ServeFile(w, r, "example.txt.gz")
	})

	http.ListenAndServe(":8080", r)
}





// Example 40: Metrics and Monitoring Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Histogram of request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(requestDuration)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Pass request to the next handler
		next.ServeHTTP(w, r)

		duration := time.Since(start).Seconds()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

func main() {
	r := mux.NewRouter()

	// Metrics endpoint for Prometheus
	r.Handle("/metrics", promhttp.Handler())

	// Apply metrics middleware to all routes
	r.Use(metricsMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Metrics Middleware!")
	})

	http.ListenAndServe(":8080", r)
}





// Example 41: Serving Static Files with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Serve static files from the "static" directory
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.ListenAndServe(":8080", r)
}





// Example 42: CORS Middleware with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	r := mux.NewRouter()

	// CORS middleware
	corsHandler := cors.Default().Handler

	// Apply CORS middleware to all routes
	r.Use(corsHandler)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Gorilla Mux with CORS Middleware!"))
	})

	http.ListenAndServe(":8080", r)
}





// Example 43: Custom Error Handling Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func errorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply custom error handling middleware to all routes
	r.Use(errorMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Simulate a panic for demonstration
		panic("something went wrong")
	})

	http.ListenAndServe(":8080", r)
}





// Example 44: Request Timeout Handling Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func timeoutMiddleware(timeout time.Duration) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, timeout, "Request Timeout")
	}
}

func main() {
	r := mux.NewRouter()

	// Apply timeout middleware to all routes with a 5-second timeout
	r.Use(timeoutMiddleware(5 * time.Second))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // Simulate some work
		fmt.Fprintf(w, "Request completed within timeout")
	})

	http.ListenAndServe(":8080", r)
}





// Example 45: Handling WebSockets with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	for {
		// Echo incoming WebSocket messages
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(messageType, p); err != nil {
			return
		}
	}
}

func main() {
	r := mux.NewRouter()

	// WebSocket endpoint
	r.HandleFunc("/ws", websocketHandler)

	http.ListenAndServe(":8080", r)
}





// Example 46: Custom 404 Not Found Page with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Custom 404 Page Not Found"))
}

func main() {
	r := mux.NewRouter()

	// Handle 404 Not Found with custom handler
	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Gorilla Mux with Custom 404 Page Handling!"))
	})

	http.ListenAndServe(":8080", r)
}





// Example 47: Secure Headers Middleware with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/unrolled/secure"
)

func secureHeadersMiddleware(next http.Handler) http.Handler {
	secureMiddleware := secure.New(secure.Options{
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
	})

	return secureMiddleware.Handler(next)
}

func main() {
	r := mux.NewRouter()

	// Apply secure headers middleware to all routes
	r.Use(secureHeadersMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Gorilla Mux with Secure Headers Middleware!"))
	})

	http.ListenAndServe(":8080", r)
}





// Example 48: Session Management Middleware with Gorilla Mux

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("secret"))

func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")

		// Set session values
		if session.Values["authenticated"] == nil {
			session.Values["authenticated"] = false
		}

		// Save the session
		session.Save(r, w)

		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Apply session management middleware to all routes
	r.Use(sessionMiddleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		if session.Values["authenticated"].(bool) {
			fmt.Fprintf(w, "Authenticated User")
		} else {
			fmt.Fprintf(w, "Unauthenticated User")
		}
	})

	http.ListenAndServe(":8080", r)
}





// Example 49: Handling Redirects with Gorilla Mux

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Redirect from "/old" to "/new"
	r.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new", http.StatusMovedPermanently)
	})

	r.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Redirected from /old"))
	})

	http.ListenAndServe(":8080", r)
}





// Example 50: Integration with Negroni Middleware using Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Example Negroni middleware
	n := negroni.Classic()

	// Use Negroni middleware with Gorilla Mux router
	n.UseHandler(r)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux with Negroni Middleware!")
	})

	http.ListenAndServe(":8080", n)
}






//Example 51: Basic Routing with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router instance
	r := mux.NewRouter()

	// Define a handler function
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Gorilla Mux!")
	}

	// Register the handler function for the "/" route
	r.HandleFunc("/", handler)

	// Start the HTTP server
	http.ListenAndServe(":8080", r)
}





//Example 52: Handling Route Parameters with Gorilla Mux

package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	// Create a new router instance
	r := mux.NewRouter()

	// Define a handler function for "/hello/{name}"
	handler := func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		name := vars["name"]
		fmt.Fprintf(w, "Hello, %s!", name)
	}

	// Register the handler function for the "/hello/{name}" route
	r.HandleFunc("/hello/{name}", handler)

	// Start the HTTP server
	http.ListenAndServe(":8080", r)
}













// Connect to a SQLite database
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
}



// Define a User model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}



// Create a record in the database
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	user := User{Name: "John"}
	db.Create(&user)
}



// Read a record from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.First(&user, 1) // find user with integer primary key
	fmt.Println(user)
}



// Update a record in the database
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.First(&user, 1) // find user with integer primary key
	user.Name = "Jane"
	db.Save(&user)
}



// Delete a record from the database
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.First(&user, 1) // find user with integer primary key
	db.Delete(&user)
}



// Batch insert multiple records into the database
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	users := []User{
		{Name: "Alice"},
		{Name: "Bob"},
		{Name: "Charlie"},
	}
	db.Create(&users)
}




// Find records with conditions from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Where("name = ?", "Alice").Find(&users)
	fmt.Println(users)
}



// Find records with multiple conditions from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Where("name = ? AND id = ?", "Alice", 1).Find(&users)
	fmt.Println(users)
}



// Find records with IN condition from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Where("name IN ?", []string{"Alice", "Bob"}).Find(&users)
	fmt.Println(users)
}




// Find records with LIKE condition from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Where("name LIKE ?", "%li%").Find(&users)
	fmt.Println(users)
}





// Find records with OR condition from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Where("name = ? OR name = ?", "Alice", "Bob").Find(&users)
	fmt.Println(users)
}



// Order records by a field from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Order("name desc").Find(&users)
	fmt.Println(users)
}



// Limit the number of records fetched from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Limit(2).Find(&users)
	fmt.Println(users)
}



// Offset the records fetched from the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Offset(1).Find(&users)
	fmt.Println(users)
}



// Count the number of records in the database
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var count int64
	db.Model(&User{}).Count(&count)
	fmt.Println("Total users:", count)
}





// Execute raw SQL queries
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Raw("SELECT * FROM users WHERE name = ?", "Alice").Scan(&users)
	fmt.Println(users)
}





// Use transactions to ensure atomicity
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	tx := db.Begin()
	if err := tx.Error; err != nil {
		panic(err)
	}

	user := User{Name: "Alice"}
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		panic(err)
	}

	if err := tx.Commit().Error; err != nil {
		panic(err)
	}
}



// Eager load related models
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID uint
	Email  string
}

type User struct {
	gorm.Model
	Name    string
	Profile Profile
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Profile{})

	var user User
	db.Preload("Profile").First(&user, 1)
	fmt.Println(user)
}




// Lazy load related models
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID uint
	Email  string
}

type User struct {
	gorm.Model
	Name    string
	Profile Profile `gorm:"foreignKey:UserID"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Profile{})

	var user User
	db.First(&user, 1)
	db.Model(&user).Association("Profile").Find(&user.Profile)
	fmt.Println(user)
}




// Define one-to-many relationship
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Post struct {
	gorm.Model
	Title  string
	UserID uint
}

type User struct {
	gorm.Model
	Name  string
	Posts []Post
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Post{})

	user := User{Name: "Alice", Posts: []Post{{Title: "First Post"}, {Title: "Second Post"}}}
	db.Create(&user)

	var users []User
	db.Preload("Posts").Find(&users)
	fmt.Println(users)
}




// Define many-to-many relationship
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Role struct {
	gorm.Model
	Name  string
	Users []User `gorm:"many2many:user_roles;"`
}

type User struct {
	gorm.Model
	Name  string
	Roles []Role `gorm:"many2many:user_roles;"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Role{})

	role := Role{Name: "Admin"}
	user := User{Name: "Alice", Roles: []Role{role}}
	db.Create(&user)

	var users []User
	db.Preload("Roles").Find(&users)
	fmt.Println(users)
}



// Create table with unique constraints
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name  string `gorm:"unique"`
	Email string `gorm:"unique"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}



// Add index to a column
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string `gorm:"index"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}



// Add composite index to multiple columns
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	FirstName string `gorm:"index:idx_name"`
	LastName  string `gorm:"index:idx_name"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}




// Add a unique index to a column
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email string `gorm:"uniqueIndex"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}




// Add multiple unique indexes to a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	FirstName string `gorm:"uniqueIndex:idx_name"`
	LastName  string `gorm:"uniqueIndex:idx_name"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}



// Add foreign key constraint to a column
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID uint
	Email  string
}

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Profile{})
}




// Add NOT NULL constraint to a column
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string `gorm:"not null"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}


// Add default value to a column
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name  string
	Age   int `gorm:"default:18"`
	Email string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}


// Implement soft delete for a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	user := User{Name: "Alice"}
	db.Create(&user)

	db.Delete(&user)
}



// Find records including soft deleted ones
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Unscoped().Find(&users)
	fmt.Println(users)
}



// Paginate results using limit and offset
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var users []User
	db.Limit(2).Offset(2).Find(&users)
	fmt.Println(users)
}



// Update specific fields of a record
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.First(&user, 1)
	db.Model(&user).Update("Age", 25)
}



// Update multiple fields of a record
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.First(&user, 1)
	db.Model(&user).Updates(User{Name: "John", Age: 30})
}



// Find the first record matching conditions
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.Where("name = ?", "Alice").First(&user)
	fmt.Println(user)
}



// Find the last record matching conditions
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var user User
	db.Where("name = ?", "Alice").Last(&user)
	fmt.Println(user)
}




// Find records and preload associations
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID uint
	Email  string
}

type User struct {
	gorm.Model
	Name    string
	Profile Profile
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Profile{})

	var users []User
	db.Preload("Profile").Find(&users)
	fmt.Println(users)
}



// Find records and preload nested associations
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Profile struct {
	gorm.Model
	UserID uint
	Email  string
}

type Post struct {
	gorm.Model
	Title  string
	UserID uint
}

type User struct {
	gorm.Model
	Name    string
	Profile Profile
	Posts   []Post
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{}, &Profile{}, &Post{})

	var users []User
	db.Preload("Profile").Preload("Posts").Find(&users)
	fmt.Println(users)
}



// Scan query results into a struct
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

type Result struct {
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var result Result
	db.Table("users").Select("name, age").Where("name = ?", "Alice").Scan(&result)
	fmt.Println(result)
}





// Scan query results into a slice of structs
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

type Result struct {
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	var results []Result
	db.Table("users").Select("name, age").Where("age > ?", 20).Scan(&results)
	fmt.Println(results)
}





// Use raw SQL to insert records
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	db.Exec("INSERT INTO users (name, age) VALUES (?, ?)", "Alice", 25)
}




// Use raw SQL to update records
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	db.Exec("UPDATE users SET age = ? WHERE name = ?", 26, "Alice")
}




// Use raw SQL to delete records
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	db.Exec("DELETE FROM users WHERE name = ?", "Alice")
}




// Use Gorm hooks for actions before/after create/update/delete
package main

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
	Age  int
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	fmt.Println("Before creating:", u.Name)
	return
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})

	user := User{Name: "Alice", Age: 25}
	db.Create(&user)
}




// Define a custom primary key for a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	ID   string `gorm:"primaryKey"`
	Name string
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}





// Define a composite primary key for a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	FirstName string `gorm:"primaryKey"`
	LastName  string `gorm:"primaryKey"`
	Age       int
}

func main() {
	db, err := gorm.Open("test.db"), &gorm.Config{})
  if err != nil {
    panic("failed to connect database")
  }
  db.AutoMigrate(&User{})
}



// Define a custom table name for a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string
}

func (User) TableName() string {
	return "my_users"
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}




// Define a custom column name for a field in a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	FirstName string `gorm:"column:given_name"`
	LastName  string `gorm:"column:surname"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}




// Customize the SQL data type for a field in a model
package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name string `gorm:"type:varchar(100)"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
}










// Setup a gRPC server with unary RPC
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Setup a gRPC client and call a unary RPC
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}




// Implement server streaming RPC
package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

type StreamerServer struct{}

func (s *StreamerServer) CountNumbers(req *NumberRequest, stream Streamer_CountNumbersServer) error {
	for i := 1; i <= int(req.Number); i++ {
		if err := stream.Send(&NumberResponse{Result: int64(i)}); err != nil {
			return err
		}
		time.Sleep(time.Second) // Simulating some processing time
	}
	return nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Implement client streaming RPC
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	stream, err := client.RecordNumbers(context.Background())
	if err != nil {
		log.Fatalf("error recording numbers: %v", err)
	}

	for _, number := range []int64{1, 2, 3, 4, 5} {
		if err := stream.Send(&NumberRequest{Number: number}); err != nil {
			log.Fatalf("error sending request: %v", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("error closing stream: %v", err)
	}

	log.Printf("Sum of numbers: %d", resp.Sum)
}




// Implement bidirectional streaming RPC
package main

import (
	"context"
	"io"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

type BidirectionalServer struct{}

func (s *BidirectionalServer) Communicate(stream Bidirectional_CommunicateServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("Received message: %s", req.Message)

		if err := stream.Send(&BidirectionalResponse{Message: "Hello, " + req.Message}); err != nil {
			return err
		}
		time.Sleep(time.Second) // Simulating some processing time
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterBidirectionalServer(s, &BidirectionalServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Implement unary RPC with deadline
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Bob"})
	if err != nil {
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.DeadlineExceeded {
			log.Fatalf("timeout: %v", statusErr.Message())
		}
		log.Fatalf("error: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}




// Implement server-side interceptor
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	log.Printf("Unary RPC call: %s", info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("Unary RPC error: %v", err)
	}
	return resp, err
}

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(unaryInterceptor),
	)
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Implement client-side interceptor
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func clientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	log.Printf("Sending RPC request: %s", method)
	err := invoker(ctx, method, req, reply, cc, opts...)
	if err != nil {
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.DeadlineExceeded {
			log.Printf("RPC request timed out: %v", err)
		} else {
			log.Printf("RPC request error: %v", err)
		}
	}
	return err
}

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithUnaryInterceptor(clientInterceptor))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Charlie"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}




// Implement RPC with retry and deadline
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func retryInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err == nil || ctx.Err() != nil {
			return err
		}
		log.Printf("RPC failed: %v. Retrying...", err)
	}
}

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithUnaryInterceptor(retryInterceptor))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Charlie"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}







// Implement gRPC reflection service
package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	reflection.Register(s)
	log.Println("gRPC server with reflection started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}



// Setup a gRPC server with TLS
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	certificate, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("could not load server key pair: %v", err)
	}
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("could not read ca certificate: %v", err)
	}
	if ok := certPool.AppendCertsFromPEM(bs); !ok {
		log.Fatalf("failed to append client certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server with TLS started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Setup a gRPC client with TLS
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("could not read ca certificate: %v", err)
	}
	if ok := certPool.AppendCertsFromPEM(bs); !ok {
		log.Fatalf("failed to append client certs")
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	})
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}





// Error handling in gRPC server
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Name is required")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Unary RPC with metadata
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("Received metadata: %v", md)
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Unary RPC client with metadata
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	md := metadata.Pairs("authorization", "Bearer some-token")
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}




package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata not provided")
	}

	token := md["authorization"]
	if len(token) == 0 || token[0] != "Bearer some-token" {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return handler(ctx, req)
}

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor),
	)
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Server-side streaming RPC with authentication
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type StreamerServer struct{}

func (s *StreamerServer) ListNumbers(req *NumberRequest, stream Streamer_ListNumbersServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata not provided")
	}

	token := md["authorization"]
	if len(token) == 0 || token[0] != "Bearer some-token" {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	for i := 1; i <= int(req.Number); i++ {
		if err := stream.Send(&NumberResponse{Result: int64(i)}); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Client-side streaming RPC with authentication
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	md := metadata.Pairs("authorization", "Bearer some-token")
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	stream, err := client.RecordNumbers(ctx)
	if err != nil {
		log.Fatalf("error recording numbers: %v", err)
	}

	for _, number := range []int64{1, 2, 3, 4, 5} {
		if err := stream.Send(&NumberRequest{Number: number}); err != nil {
			log.Fatalf("error sending request: %v", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("error closing stream: %v", err)
	}

	log.Printf("Sum of numbers: %d", resp.Sum)
}





// Bidirectional streaming RPC with authentication
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type BidirectionalServer struct{}

func (s *BidirectionalServer) Chat(stream Bidirectional_ChatServer) error {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata not provided")
	}

	token := md["authorization"]
	if len(token) == 0 || token[0] != "Bearer some-token" {
		return status.Errorf(codes.Unauthenticated, "invalid token")
	}

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("Received message: %s", req.Message)

		if err := stream.Send(&BidirectionalResponse{Message: "Hello, " + req.Message}); err != nil {
			return err
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterBidirectionalServer(s, &BidirectionalServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Cancel RPC context to terminate ongoing operation
package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	select {
	case <-time.After(time.Second * 3):
		return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Unary RPC with client-side cancellation
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Bob"})
	if err != nil {
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.DeadlineExceeded {
			log.Fatalf("timeout: %v", statusErr.Message())
		}
		log.Fatalf("error: %v", err)
	}
	log.Printf("Greeting: %s", resp.Message)
}




// Unary RPC with server-side context cancellation
package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	select {
	case <-time.After(time.Second * 5):
		return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Unary RPC with context propagation
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("Received metadata: %v", md)
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Streaming RPC with deadline
package main

import (
	"context"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type StreamerServer struct{}

func (s *StreamerServer) RecordNumbers(stream Streamer_RecordNumbersServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("Received number: %d", req.Number)

		// Simulate processing time
		select {
		case <-stream.Context().Done():
			return status.Error(codes.DeadlineExceeded, "client deadline exceeded")
		default:
			if err := stream.Send(&NumberResponse{Result: req.Number * req.Number}); err != nil {
				return err
			}
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Client-side streaming RPC with deadline
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream, err := client.RecordNumbers(ctx)
	if err != nil {
		log.Fatalf("error recording numbers: %v", err)
	}

	for _, number := range []int64{1, 2, 3, 4, 5} {
		if err := stream.Send(&NumberRequest{Number: number}); err != nil {
			log.Fatalf("error sending request: %v", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("error closing stream: %v", err)
	}

	log.Printf("Sum of squares: %d", resp.Sum)
}




// Bidirectional streaming RPC with deadline
package main

import (
	"context"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BidirectionalServer struct{}

func (s *BidirectionalServer) Chat(stream Bidirectional_ChatServer) error {
	ctx := stream.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			log.Printf("Received message: %s", req.Message)

			if err := stream.Send(&BidirectionalResponse{Message: "Hello, " + req.Message}); err != nil {
				return err
			}
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterBidirectionalServer(s, &BidirectionalServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Unary RPC with custom error handling
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name cannot be empty")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Server-side streaming RPC with custom error handling
package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type StreamerServer struct{}

func (s *StreamerServer) ListNumbers(req *NumberRequest, stream Streamer_ListNumbersServer) error {
	if req.Number <= 0 {
		return status.Error(codes.InvalidArgument, "Number should be greater than zero")
	}

	for i := 1; i <= int(req.Number); i++ {
		if err := stream.Send(&NumberResponse{Result: int64(i)}); err != nil {
			return err
		}
		time.Sleep(time.Second) // Simulate processing time
	}
	return nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Client-side streaming RPC with custom error handling
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	ctx := context.Background()
	stream, err := client.RecordNumbers(ctx)
	if err != nil {
		log.Fatalf("error recording numbers: %v", err)
	}

	for _, number := range []int64{0, -1, 2, 3, 4} { // Sending invalid numbers
		if err := stream.Send(&NumberRequest{Number: number}); err != nil {
			log.Fatalf("error sending request: %v", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.InvalidArgument {
			log.Fatalf("invalid argument: %v", statusErr.Message())
		}
		log.Fatalf("error closing stream: %v", err)
	}

	log.Printf("Sum of squares: %d", resp.Sum)
}





// Bidirectional streaming RPC with custom error handling
package main

import (
	"context"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BidirectionalServer struct{}

func (s *BidirectionalServer) Chat(stream Bidirectional_ChatServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("Received message: %s", req.Message)

		if req.Message == "error" {
			return status.Error(codes.InvalidArgument, "Received 'error' message")
		}

		if err := stream.Send(&BidirectionalResponse{Message: "Hello, " + req.Message}); err != nil {
			return err
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterBidirectionalServer(s, &BidirectionalServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Handling gRPC errors on client-side
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: ""}) // Sending empty name
	if err != nil {
		statusErr, ok := status.FromError(err)
		if ok && statusErr.Code() == codes.InvalidArgument {
			log.Fatalf("invalid argument: %v", statusErr.Message())
		}
		log.Fatalf("error: %v", err)
	}

	log.Printf("Greeting: %s", resp.Message)
}





// Unary RPC with error propagation from server
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "error" {
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// Unary RPC with error handling and logging
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "" {
		err := status.Error(codes.InvalidArgument, "Name cannot be empty")
		log.Printf("Invalid request: %v", err)
		return nil, err
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// Streaming RPC with error handling and logging
package main

import (
	"context"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type StreamerServer struct{}

func (s *StreamerServer) RecordNumbers(stream Streamer_RecordNumbersServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("Received number: %d", req.Number)

		if req.Number <= 0 {
			err := status.Error(codes.InvalidArgument, "Number should be greater than zero")
			log.Printf("Invalid request: %v", err)
			return err
		}

		if err := stream.Send(&NumberResponse{Result: req.Number * req.Number}); err != nil {
			return err
		}
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Handling gRPC errors with retry mechanism
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	retryAttempts := 3
	for attempt := 1; attempt <= retryAttempts; attempt++ {
		client := NewGreeterClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		resp, err := client.SayHello(ctx, &HelloRequest{Name: "error"}) // Simulating error scenario
		if err != nil {
			statusErr, ok := status.FromError(err)
			if ok && statusErr.Code() == codes.Internal {
				log.Printf("Attempt %d: Internal server error - %v", attempt, statusErr.Message())
				if attempt < retryAttempts {
					log.Println("Retrying...")
					time.Sleep(2 * time.Second)
					continue
				}
			}
			log.Fatalf("error: %v", err)
		}

		log.Printf("Greeting: %s", resp.Message)
		break
	}
}





// Unary RPC with TLS encryption
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certFile := "server.crt"
	keyFile := "server.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started with TLS on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// Code for client-side streaming RPC with TLS encryption


package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certFile := "client.crt"
	keyFile := "client.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load client certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	})

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	// Perform client-side streaming RPC operations here...
}





// Bidirectional streaming RPC with TLS encryption
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certFile := "client.crt"
	keyFile := "client.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load client certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	})

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewBidirectionalClient(conn)
	ctx := context.Background()
	stream, err := client.Chat(ctx)
	if err != nil {
		log.Fatalf("error opening stream: %v", err)
	}

	// Perform bidirectional streaming RPC operations here...
}





// Server-side streaming RPC with TLS encryption
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certFile := "server.crt"
	keyFile := "server.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started with TLS on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// gRPC with interceptors for logging
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	log.Printf("Received request: %v", req)
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "Name cannot be empty")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Printf("gRPC method: %s, request: %v", info.FullMethod, req)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("gRPC method: %s, error: %v", info.FullMethod, err)
	}
	return resp, err
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(loggingInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}







// gRPC with authentication interceptor
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func authInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	creds, err := credentials.ParseAuthorizationHeader(ctx, "Bearer")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
	}
	// Perform authentication logic here with `creds`
	log.Printf("Authenticated with credentials: %v", creds)
	return handler(ctx, req)
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC with custom metadata
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("Received metadata: %v", md)
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC with cancellation propagation
package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		time.Sleep(2 * time.Second) // Simulate processing time
		return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// gRPC with context metadata propagation
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("Received metadata: %v", md)
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}




// gRPC with deadline propagation on client-side
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Printf("Greeting: %s", resp.Message)
}




// gRPC with unary interceptor for logging
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	log.Printf("Received request: %v", req)
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Printf("gRPC method: %s, request: %v", info.FullMethod, req)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("gRPC method: %s, error: %v", info.FullMethod, err)
	}
	return resp, err
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(loggingInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// gRPC with server-side streaming and TLS encryption
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type StreamerServer struct{}

func (s *StreamerServer) RecordNumbers(req *NumberRequest, stream Streamer_RecordNumbersServer) error {
	for i := int64(1); i <= req.Number; i++ {
		if err := stream.Send(&NumberResponse{Result: i}); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	certFile := "server.crt"
	keyFile := "server.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterStreamerServer(s, &StreamerServer{})
	log.Println("gRPC server started with TLS on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC with client-side streaming and TLS encryption
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type StreamerClient struct{}

func (s *StreamerClient) ComputeAverage(stream Streamer_ComputeAverageClient) error {
	numbers := []int64{1, 2, 3, 4, 5} // Example numbers
	for _, num := range numbers {
		if err := stream.Send(&NumberRequest{Number: num}); err != nil {
			return err
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	log.Printf("Average: %.2f", resp.Average)
	return nil
}

func main() {
	certFile := "client.crt"
	keyFile := "client.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load client certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	})

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewStreamerClient(conn)
	stream, err := client.ComputeAverage(context.Background())
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		log.Printf("Received response: %v", resp)
	}
}




// gRPC with custom error handling
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Name cannot be empty")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// gRPC server with unary interceptor for authorization
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func authInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Example: Perform authorization logic here
	if token := ctx.Value("token"); token == nil || token.(string) != "valid_token" {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
	}
	return handler(ctx, req)
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC server with unary interceptor for logging and recovery
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	panic("test panic") // Simulate a panic
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	log.Printf("gRPC method: %s, request: %v", info.FullMethod, req)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
		}
	}()
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("gRPC method: %s, error: %v", info.FullMethod, err)
	}
	return resp, err
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(loggingInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC client with retry and timeout
package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func main() {
	conn, err := grpc.Dial(
		"localhost:50051",
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(retryInterceptor),
	)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Printf("Greeting: %s", resp.Message)
}

func retryInterceptor(
	ctx context.Context,
	method string,
	req interface{},
	reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if err == nil {
			return nil
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unavailable {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return status.Error(codes.Unavailable, "Service unavailable")
}






// gRPC server with TLS and mutual authentication
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	certFile := "server.crt"
	keyFile := "server.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started with TLS on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC client with custom metadata
package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	md := metadata.Pairs("authorization", "Bearer token")
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Printf("Greeting: %s", resp.Message)
}





// gRPC server with custom metadata interceptor
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		log.Printf("Received metadata: %v", md)
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func metadataInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}
	md.Append("server-interceptor", "true")
	newCtx := metadata.NewIncomingContext(ctx, md)
	return handler(newCtx, req)
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(metadataInterceptor))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}






// gRPC server with TLS and custom error handling
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/credentials"
)

type GreeterServer struct{}

func (s *GreeterServer) SayHello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	if req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Name cannot be empty")
	}
	return &HelloResponse{Message: "Hello, " + req.Name + "!"}, nil
}

func main() {
	certFile := "server.crt"
	keyFile := "server.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterGreeterServer(s, &GreeterServer{})
	log.Println("gRPC server started with TLS on port 50051...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}





// gRPC client with TLS and custom timeout
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	certFile := "client.crt"
	keyFile := "client.key"
	caFile := "ca.crt"

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load client certificate: %v", err)
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	})

	conn, err := grpc.Dial(
		"localhost:50051",
		grpc.WithTransportCredentials(creds),
		grpc.WithTimeout(2 * time.Second),
	)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := NewGreeterClient(conn)
	ctx := context.Background()

	resp, err := client.SayHello(ctx, &HelloRequest{Name: "Alice"})
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	log.Printf("Greeting: %s", resp.Message)
}










// Import the Prometheus package
package main

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)



// Create a Counter metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var requestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
    Name: "requests_total",
    Help: "Total number of requests.",
})




// Register a Counter metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(requestsTotal)
}





// Increment a Counter metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    requestsTotal.Inc()
}





// Create a Gauge metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var temperatureGauge = prometheus.NewGauge(prometheus.GaugeOpts{
    Name: "temperature",
    Help: "Current temperature.",
})





// Set a Gauge metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    temperatureGauge.Set(23.5)
}





// Increment a Gauge metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    temperatureGauge.Inc()
}





// Decrement a Gauge metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    temperatureGauge.Dec()
}





// Create a Histogram metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var requestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
    Name:    "request_duration_seconds",
    Help:    "Histogram of request duration.",
    Buckets: prometheus.DefBuckets,
})





// Observe a value in Histogram metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    requestDuration.Observe(0.23)
}





// Create a Summary metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var responseSize = prometheus.NewSummary(prometheus.SummaryOpts{
    Name: "response_size_bytes",
    Help: "Summary of response sizes.",
})





// Observe a value in Summary metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    responseSize.Observe(512)
}





// Create a CounterVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var requestsTotalVec = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "requests_total",
        Help: "Total number of requests.",
    },
    []string{"method", "endpoint"},
)





// Register a CounterVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(requestsTotalVec)
}






// Increment a CounterVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    requestsTotalVec.WithLabelValues("GET", "/home").Inc()
}





// Create a GaugeVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var temperatureGaugeVec = prometheus.NewGaugeVec(
    prometheus.GaugeOpts{
        Name: "temperature",
        Help: "Current temperature.",
    },
    []string{"location"},
)





// Register a GaugeVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(temperatureGaugeVec)
}





// Set a value in GaugeVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    temperatureGaugeVec.WithLabelValues("server_room").Set(22.3)
}





// Create a HistogramVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var requestDurationVec = prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "request_duration_seconds",
        Help:    "Histogram of request duration.",
        Buckets: prometheus.DefBuckets,
    },
    []string{"method", "endpoint"},
)





// Register a HistogramVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(requestDurationVec)
}





// Observe a value in HistogramVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    requestDurationVec.WithLabelValues("GET", "/home").Observe(0.34)
}





// Create a SummaryVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var responseSizeVec = prometheus.NewSummaryVec(
    prometheus.SummaryOpts{
        Name: "response_size_bytes",
        Help: "Summary of response sizes.",
    },
    []string{"endpoint"},
)





// Register a SummaryVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(responseSizeVec)
}





// Observe a value in SummaryVec metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    responseSizeVec.WithLabelValues("/home").Observe(420)
}





// Create a custom Collector
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

type MyCollector struct {
    fooMetric *prometheus.Desc
}

func NewMyCollector() *MyCollector {
    return &MyCollector{
        fooMetric: prometheus.NewDesc("foo_metric", "Description of foo metric", nil, nil),
    }
}

func (collector *MyCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- collector.fooMetric
}

func (collector *MyCollector) Collect(ch chan<- prometheus.Metric) {
    ch <- prometheus.MustNewConstMetric(collector.fooMetric, prometheus.GaugeValue, 1.0)
}





// Register a custom Collector
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(NewMyCollector())
}





// Create an HTTP handler for metrics
package main

import (
    "net/http"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    http.Handle("/metrics", promhttp.Handler())
    http.ListenAndServe(":8080", nil)
}






// Start an HTTP server to expose metrics
package main

import (
    "log"
    "net/http"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    http.Handle("/metrics", promhttp.Handler())
    log.Fatal(http.ListenAndServe(":8080", nil))
}






// Create a constant Counter metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var constCounter = prometheus.NewCounter(prometheus.CounterOpts{
    Name: "const_counter",
    Help: "A counter that is set to a constant value.",
})





// Set a constant Counter metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    constCounter.Add(100)
}





// Use PushGateway to push metrics
package main

import (
    "log"
    "github.com/prometheus/client_golang/prometheus/push"
    "github.com/prometheus/client_golang/prometheus"
)

var requestsTotal = prometheus.NewCounter(prometheus.CounterOpts{
    Name: "requests_total",
    Help: "Total number of requests.",
})

func main() {
    prometheus.MustRegister(requestsTotal)
    pusher := push.New("http://localhost:9091", "my_job").Collector(requestsTotal)
    if err := pusher.Push(); err != nil {
        log.Fatal("Could not push to PushGateway:", err)
    }
}





// Create a CounterFunc metric
package main

import (
    "runtime"
    "github.com/prometheus/client_golang/prometheus"
)

var goRoutineCounter = prometheus.NewCounterFunc(prometheus.CounterOpts{
    Name: "go_goroutines",
    Help: "Number of goroutines.",
}, func() float64 {
    return float64(runtime.NumGoroutine())
})





// Register a CounterFunc metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(goRoutineCounter)
}





// Create a GaugeFunc metric
package main

import (
    "runtime"
    "github.com/prometheus/client_golang/prometheus"
)

var memoryUsageGauge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
    Name: "memory_usage_bytes",
    Help: "Memory usage in bytes.",
}, func() float64 {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    return float64(m.Alloc)
})





// Register a GaugeFunc metric
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(memoryUsageGauge)
}





// Create a Summary with Objectives
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var latencySummary = prometheus.NewSummary(prometheus.SummaryOpts{
    Name:       "latency_seconds",
    Help:       "Summary of latencies.",
    Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
})





// Observe a value in Summary with Objectives
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    latencySummary.Observe(1.2)
}





// Create a CounterVec with dynamic labels
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

var errorsCounterVec = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "errors_total",
        Help: "Total number of errors.",
    },
    []string{"type"},
)





// Register a CounterVec with dynamic labels
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func init() {
    prometheus.MustRegister(errorsCounterVec)
}





// Increment a CounterVec with dynamic labels
package main

import (
    "github.com/prometheus/client_golang/prometheus"
)

func main() {
    errorsCounterVec.WithLabelValues("network").Inc()
}










package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Ping Redis to check the connection.
    pong, err := rdb.Ping(ctx).Result()
    fmt.Println(pong, err)

    // Set a key-value pair.
    err = rdb.Set(ctx, "key1", "value1", 0).Err()
    if err != nil {
        panic(err)
    }

    // Get the value of the key.
    val, err := rdb.Get(ctx, "key1").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("key1", val)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Push values to a list.
    err := rdb.LPush(ctx, "list1", "value1", "value2", "value3").Err()
    if err != nil {
        panic(err)
    }

    // Retrieve list elements.
    vals, err := rdb.LRange(ctx, "list1", 0, -1).Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("list1:", vals)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Set multiple fields in a hash.
    err := rdb.HSet(ctx, "hash1", map[string]interface{}{
        "field1": "value1",
        "field2": "value2",
    }).Err()
    if err != nil {
        panic(err)
    }

    // Retrieve hash values.
    vals, err := rdb.HGetAll(ctx, "hash1").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("hash1:", vals)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Add members to a set.
    err := rdb.SAdd(ctx, "set1", "member1", "member2", "member3").Err()
    if err != nil {
        panic(err)
    }

    // Retrieve set members.
    members, err := rdb.SMembers(ctx, "set1").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("set1 members:", members)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Add members with scores to a sorted set.
    err := rdb.ZAdd(ctx, "sortedset1", &redis.Z{
        Score:  1.0,
        Member: "member1",
    }, &redis.Z{
        Score:  2.0,
        Member: "member2",
    }).Err()
    if err != nil {
        panic(err)
    }

    // Retrieve sorted set members by rank.
    vals, err := rdb.ZRange(ctx, "sortedset1", 0, -1).Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("sortedset1 members:", vals)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Subscribe to a channel.
    pubsub := rdb.Subscribe(ctx, "channel1")
    defer pubsub.Close()

    // Wait for confirmation that subscription is created before publishing anything.
    _, err := pubsub.Receive(ctx)
    if err != nil {
        panic(err)
    }

    // Publish a message to the channel.
    err = rdb.Publish(ctx, "channel1", "hello world").Err()
    if err != nil {
        panic(err)
    }

    // Read message from the channel.
    msg, err := pubsub.ReceiveMessage(ctx)
    if err != nil {
        panic(err)
    }
    fmt.Println("Message received:", msg.Payload)
}





package main

import (
    "context"
    "fmt"
    "time"

    "github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Set a key that expires in 10 seconds.
    err := rdb.Set(ctx, "key2", "value2", 10*time.Second).Err()
    if err != nil {
        panic(err)
    }

    // Retrieve the value of the key immediately.
    val, err := rdb.Get(ctx, "key2").Result()
    if err != nil {
        if err == redis.Nil {
            fmt.Println("key2 does not exist")
        } else {
            panic(err)
        }
    } else {
        fmt.Println("key2", val)
    }

    // Wait for key to expire.
    time.Sleep(11 * time.Second)

    // Try to retrieve the expired key.
    val, err = rdb.Get(ctx, "key2").Result()
    if err != nil {
        if err == redis.Nil {
            fmt.Println("key2 does not exist after expiry")
        } else {
            panic(err)
        }
    } else {
        fmt.Println("key2", val)
    }
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Create a pipeline.
    pipe := rdb.Pipeline()

    // Execute multiple commands in a pipeline.
    pipe.Set(ctx, "key3", "value3", 0)
    pipe.Get(ctx, "key3")

    // Execute the pipeline and retrieve results.
    _, err := pipe.Exec(ctx)
    if err != nil {
        panic(err)
    }

    // Retrieve the value of the key from Redis.
    val, err := rdb.Get(ctx, "key3").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("key3", val)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Begin a transaction.
    tx := rdb.TxPipeline()

    // Queue commands inside the transaction.
    tx.Set(ctx, "key4", "value4", 0)
    tx.Get(ctx, "key4")

    // Execute the transaction.
    _, err := tx.Exec(ctx)
    if err != nil {
        panic(err)
    }

    // Retrieve the value of the key from Redis.
    val, err := rdb.Get(ctx, "key4").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("key4", val)
}





package main

import (
    "fmt"
    "github.com/go-redis/redis/v8"
)

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Define a Lua script.
    luaScript := `
        local val = redis.call('GET', KEYS[1])
        return val
    `

    // Load the Lua script.
    script := redis.NewScript(luaScript)

    // Execute the Lua script.
    val, err := script.Run(ctx, rdb, []string{"key1"}).Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("Lua script result:", val)
}





package main

import (
    "context"
    "fmt"
    "github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
    // Connect to Redis Cluster.
    rdb := redis.NewClusterClient(&redis.ClusterOptions{
        Addrs: []string{"localhost:7000", "localhost:7001"}, // Redis cluster nodes
    })

    // Set a key-value pair in Redis Cluster.
    err := rdb.Set(ctx, "key5", "value5", 0).Err()
    if err != nil {
        panic(err)
    }

    // Get the value of the key from Redis Cluster.
    val, err := rdb.Get(ctx, "key5").Result()
    if err != nil {
        panic(err)
    }
    fmt.Println("key5", val)
}





package main

import (
    "context"
    "fmt"
    "github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
    // Connect to Redis.
    rdb := redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
        DB:   0,                // Use default DB
    })

    // Set keys for demo purpose.
    for i := 0; i < 10; i++ {
        key := fmt.Sprintf("key%d", i)
        err := rdb.Set(ctx, key, fmt.Sprintf("value%d", i), 0).Err()
        if err != nil {
            panic(err)
        }
    }

    // Use SCAN to iterate over keys.
    cursor := uint64(0)
    for {
        keys, nextCursor, err := rdb.Scan(ctx, cursor, "key*", 10).Result()
        if err != nil {
            panic(err)
        }
        for _, key := range keys {
            val, err := rdb.Get(ctx, key).Result()
            if err != nil {
                panic(err)
            }
            fmt.Printf("%s: %s\n", key, val)
        }
        cursor = nextCursor
        if cursor == 0 {
            break
        }
    }
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set bits in a bitmap.
	err := rdb.SetBit(ctx, "bitmap1", 0, 1).Err()
	if err != nil {
		panic(err)
	}

	err = rdb.SetBit(ctx, "bitmap1", 2, 1).Err()
	if err != nil {
		panic(err)
	}

	// Get bits from the bitmap.
	bit, err := rdb.GetBit(ctx, "bitmap1", 0).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Bit at index 0:", bit)

	bit, err = rdb.GetBit(ctx, "bitmap1", 1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Bit at index 1:", bit)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add elements to a HyperLogLog.
	err := rdb.PFAdd(ctx, "hll1", "elem1", "elem2", "elem3").Err()
	if err != nil {
		panic(err)
	}

	// Count unique elements in the HyperLogLog.
	count, err := rdb.PFCount(ctx, "hll1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("HyperLogLog count:", count)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add locations to a Geo set.
	geo := []*redis.GeoLocation{
		{Name: "location1", Longitude: 13.361389, Latitude: 38.115556},
		{Name: "location2", Longitude: 15.087269, Latitude: 37.502669},
	}
	err := rdb.GeoAdd(ctx, "locations", geo...).Err()
	if err != nil {
		panic(err)
	}

	// Get Geo coordinates.
	coords, err := rdb.GeoPos(ctx, "locations", "location1", "location2").Result()
	if err != nil {
		panic(err)
	}
	for _, coord := range coords {
		fmt.Printf("Location: %s, Latitude: %f, Longitude: %f\n", coord.Name, coord.Latitude, coord.Longitude)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add entries to a Redis Stream.
	_, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: "mystream",
		Values: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		},
	}).Result()
	if err != nil {
		panic(err)
	}

	// Read entries from the Redis Stream.
	streams, err := rdb.XRange(ctx, "mystream", "-", "+").Result()
	if err != nil {
		panic(err)
	}
	for _, msg := range streams {
		fmt.Printf("Message ID: %s, Fields: %v\n", msg.ID, msg.Values)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Define a Lua script.
	luaScript := `
        local val = redis.call('GET', KEYS[1])
        return val
    `

	// Load the Lua script.
	script := redis.NewScript(luaScript)

	// Load the script and get its SHA1 hash.
	sha1, err := script.Load(ctx, rdb).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Lua script SHA1:", sha1)

	// Execute the Lua script using EvalSha.
	val, err := rdb.EvalSha(ctx, sha1, []string{"key1"}).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("EvalSha result:", val)
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Create Redis client options with custom configurations.
	opt := &redis.Options{
		Addr:         "localhost:6379", // Redis server address
		Password:     "",               // no password set
		DB:           0,                // use default DB
		MaxRetries:   3,                // retry up to 3 times
		DialTimeout:  5 * time.Second,  // connect timeout
		ReadTimeout:  3 * time.Second,  // read timeout
		WriteTimeout: 3 * time.Second,  // write timeout
		PoolSize:     10,               // connection pool size
		PoolTimeout:  4 * time.Second,  // connection pool timeout
	}

	// Connect to Redis with custom options.
	rdb := redis.NewClient(opt)

	// Ping Redis to check the connection.
	pong, err := rdb.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Ping:", pong)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Subscribe to a channel with a context.
	pubsub := rdb.Subscribe(ctx, "channel1")
	defer pubsub.Close()

	// Wait for confirmation that subscription is created before publishing anything.
	_, err := pubsub.Receive(ctx)
	if err != nil {
		panic(err)
	}

	// Publish a message to the channel.
	err = rdb.Publish(ctx, "channel1", "hello world").Err()
	if err != nil {
		panic(err)
	}

	// Read message from the channel.
	msg, err := pubsub.ReceiveMessage(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println("Message received:", msg.Payload)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Create a pipeline for atomic counter.
	pipe := rdb.Pipeline()

	// Increment the counter multiple times.
	for i := 0; i < 5; i++ {
		pipe.Incr(ctx, "counter")
	}

	// Execute the pipeline and retrieve results.
	_, err := pipe.Exec(ctx)
	if err != nil {
		panic(err)
	}

	// Retrieve the value of the counter from Redis.
	val, err := rdb.Get(ctx, "counter").Int()
	if err != nil {
		panic(err)
	}
	fmt.Println("Counter value:", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Define a Lua script for atomic operations.
	luaScript := `
        local current = redis.call('GET', KEYS[1])
        local amount = tonumber(ARGV[1])
        local new = current and tonumber(current) + amount or amount
        redis.call('SET', KEYS[1], new)
        return new
    `

	// Load the Lua script.
	script := redis.NewScript(luaScript)

	// Execute the Lua script atomically.
	val, err := script.Run(ctx, rdb, []string{"counter"}, 5).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Counter value after Lua script:", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Begin a transaction.
	tx := rdb.TxPipeline()

	// Queue commands inside the transaction.
	tx.Set(ctx, "key1", "value1", 0)
	tx.Set(ctx, "key2", "value2", 0)

	// Execute the transaction.
	_, err := tx.Exec(ctx)
	if err != nil {
		panic(err)
	}

	// Retrieve values of keys from Redis.
	val1, err := rdb.Get(ctx, "key1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("key1", val1)

	val2, err := rdb.Get(ctx, "key2").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("key2", val2)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Create a context with cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a pipeline with context.
	pipe := rdb.PipelineWithContext(ctx)

	// Set a key-value pair.
	pipe.Set(ctx, "key3", "value3", 0)

	// Get the value of the key.
	pipe.Get(ctx, "key3")

	// Execute the pipeline and retrieve results.
	cmds, err := pipe.Exec(ctx)
	if err != nil {
		panic(err)
	}

	// Access results from individual commands.
	setResult := cmds[0].(*redis.StatusCmd)
	fmt.Println("SET result:", setResult)

	getResult := cmds[1].(*redis.StringCmd)
	val, err := getResult.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("GET result:", val)
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Create a connection pool.
	pool := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Redis server address
		Password: "",               // no password set
		DB:       0,                // use default DB
		PoolSize: 10,               // connection pool size
	})

	// Close the connection pool after program execution.
	defer pool.Close()

	// Connect to Redis using the connection pool.
	ctx := context.Background()
	err := pool.Ping(ctx).Err()
	if err != nil {
		panic(err)
	}

	// Example operations with connection pooling.
	err = pool.Set(ctx, "key1", "value1", 0).Err()
	if err != nil {
		panic(err)
	}

	val, err := pool.Get(ctx, "key1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("key1", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Key to watch for transactions.
	key := "watch_key"

	// Begin a transaction with Watch.
	tx := rdb.Watch(context.Background(), func(tx *redis.Tx) error {
		// Get the current value of the key.
		currVal, err := tx.Get(context.Background(), key).Result()
		if err != nil && err != redis.Nil {
			return err
		}

		// Perform transaction operations.
		pipe := tx.TxPipeline()
		pipe.Set(context.Background(), key, "new_value", 0)

		// Execute the transaction.
		_, err = pipe.Exec(context.Background())
		if err != nil {
			return err
		}

		return nil
	}, key)

	// Check for transaction errors.
	if tx.Err() != nil {
		panic(tx.Err())
	}

	// Retrieve the new value of the key from Redis.
	val, err := rdb.Get(context.Background(), key).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("New value of key:", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members with scores to a sorted set.
	err := rdb.ZAdd(context.Background(), "sortedset1", &redis.Z{
		Score:  1.0,
		Member: "member1",
	}, &redis.Z{
		Score:  2.0,
		Member: "member2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve sorted set members with scores.
	vals, err := rdb.ZRangeWithScores(context.Background(), "sortedset1", 0, -1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Sorted set members with scores:")
	for _, z := range vals {
		fmt.Printf("Member: %s, Score: %f\n", z.Member, z.Score)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set keys for demo purpose.
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key%d", i)
		err := rdb.Set(context.Background(), key, fmt.Sprintf("value%d", i), 0).Err()
		if err != nil {
			panic(err)
		}
	}

	// Use SCAN to iterate over keys.
	var cursor uint64
	var keys []string
	for {
		var err error
		keys, cursor, err = rdb.Scan(context.Background(), cursor, "key*", 10).Result()
		if err != nil {
			panic(err)
		}
		for _, key := range keys {
			val, err := rdb.Get(context.Background(), key).Result()
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s: %s\n", key, val)
		}
		if cursor == 0 {
			break
		}
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set multiple fields in a hash.
	err := rdb.HSet(context.Background(), "hash1", map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve all fields and values of the hash.
	vals, err := rdb.HGetAll(context.Background(), "hash1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("All fields and values of hash1:")
	for field, value := range vals {
		fmt.Printf("%s: %s\n", field, value)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
			Addr: "localhost:6379", // Redis server address
			DB:   0,                // Use default DB
	})

	// Add members to a set.
	err := rdb.SAdd(context.Background(), "set1", "member1", "member2", "member3").Err()
	if err != nil {
			panic(err)
	}

	// Retrieve all members of the set.
	vals, err := rdb.SMembers(context.Background(), "set1").Result()
	if err != nil {
			panic(err)
	}
	fmt.Println("All members of set1:")
	for _, member := range vals {
			fmt.Println(member)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members with scores to a sorted set.
	err := rdb.ZAdd(context.Background(), "sortedset2", &redis.Z{
		Score:  1.0,
		Member: "member1",
	}, &redis.Z{
		Score:  2.0,
		Member: "member2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve members within a specific score range from the sorted set.
	vals, err := rdb.ZRangeByScore(context.Background(), "sortedset2", &redis.ZRangeBy{
		Min: "1",
		Max: "2",
	}).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members within score range in sortedset2:")
	for _, member := range vals {
		fmt.Println(member)
	}
}





package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v8"
)

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Create a user object.
	user := User{
		ID:   "1",
		Name: "John Doe",
		Age:  30,
	}

	// Marshal user object to JSON and set it in Redis.
	userJSON, err := json.Marshal(user)
	if err != nil {
		panic(err)
	}
	err = rdb.Set(context.Background(), "user1", userJSON, 0).Err()
	if err != nil {
		panic(err)
	}

	// Get JSON data from Redis and unmarshal it into a user object.
	val, err := rdb.Get(context.Background(), "user1").Result()
	if err != nil {
		panic(err)
	}
	var retrievedUser User
	err = json.Unmarshal([]byte(val), &retrievedUser)
	if err != nil {
		panic(err)
	}
	fmt.Println("Retrieved user from Redis:")
	fmt.Printf("ID: %s, Name: %s, Age: %d\n", retrievedUser.ID, retrievedUser.Name, retrievedUser.Age)
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Push items into a list.
	err := rdb.LPush(context.Background(), "list1", "item1", "item2", "item3").Err()
	if err != nil {
		panic(err)
	}

	// Pop items from the list with BRPOP, which blocks until an item is available.
	for {
		result, err := rdb.BRPop(context.Background(), 0*time.Second, "list1").Result()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Popped item: %v\n", result)
	}
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set a key that expires in 5 seconds using SETEX.
	err := rdb.SetEX(context.Background(), "key2", "value2", 5*time.Second).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve the value of the key immediately.
	val, err := rdb.Get(context.Background(), "key2").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("key2", val)

	// Wait for key to expire.
	time.Sleep(6 * time.Second)

	// Try to retrieve the expired key.
	val, err = rdb.Get(context.Background(), "key2").Result()
	if err != nil {
		if err == redis.Nil {
			fmt.Println("key2 does not exist after expiry")
		} else {
			panic(err)
		}
	} else {
		fmt.Println("key2", val)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Increment a counter using INCR.
	_, err := rdb.Incr(context.Background(), "counter").Result()
	if err != nil {
		panic(err)
	}

	// Retrieve the value of the counter.
	val, err := rdb.Get(context.Background(), "counter").Int()
	if err != nil {
		panic(err)
	}
	fmt.Println("Counter value:", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Ping Redis to check connectivity.
	pong, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Ping:", pong)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set a key in Redis.
	err := rdb.Set(context.Background(), "key1", "value1", 0).Err()
	if err != nil {
		panic(err)
	}

	// Check if key exists using EXISTS.
	exists, err := rdb.Exists(context.Background(), "key1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Key exists:", exists)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set multiple fields in a hash using HMSET.
	err := rdb.HMSet(context.Background(), "hash2", map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve all fields and values of the hash using HGETALL.
	vals, err := rdb.HGetAll(context.Background(), "hash2").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("All fields and values of hash2:")
	for field, value := range vals {
		fmt.Printf("%s: %s\n", field, value)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set a field in a hash only if it does not exist using HSETNX.
	set, err := rdb.HSetNX(context.Background(), "hash3", "field1", "value1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("HSETNX result:", set)

	// Attempt to set the same field again.
	set, err = rdb.HSetNX(context.Background(), "hash3", "field1", "new_value").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("HSETNX result:", set)

	// Retrieve the value of the field.
	val, err := rdb.HGet(context.Background(), "hash3", "field1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Value of field1 in hash3:", val)
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set a key with an expiration using SETEX.
	err := rdb.SetEX(context.Background(), "key3", "value3", 10*time.Second).Err()
	if err != nil {
		panic(err)
	}

	// Get the TTL (time-to-live) of the key.
	ttl, err := rdb.TTL(context.Background(), "key3").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("TTL of key3:", ttl)

	// Get the PTTL (time-to-live in milliseconds) of the key.
	pttl, err := rdb.PTTL(context.Background(), "key3").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("PTTL of key3:", pttl)

	// Sleep for 11 seconds to let the key expire.
	time.Sleep(11 * time.Second)

	// Check if the key still exists.
	exists, err := rdb.Exists(context.Background(), "key3").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Key3 exists:", exists)
}





package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Create a subscriber.
	pubsub := rdb.Subscribe(context.Background(), "channel1")

	// Go routine to handle messages received.
	go func() {
		for {
			msg, err := pubsub.ReceiveMessage(context.Background())
			if err != nil {
				panic(err)
			}
			fmt.Printf("Message received on channel %s: %s\n", msg.Channel, msg.Payload)
		}
	}()

	// Publish messages to the channel.
	for i := 0; i < 5; i++ {
		err := rdb.Publish(context.Background(), "channel1", fmt.Sprintf("message%d", i+1)).Err()
		if err != nil {
			panic(err)
		}
		time.Sleep(1 * time.Second) // Add delay between publishes for demonstration
	}

	// Unsubscribe from the channel.
	err := pubsub.Unsubscribe(context.Background(), "channel1")
	if err != nil {
		panic(err)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Push items into a list.
	err := rdb.LPush(context.Background(), "list2", "item1", "item2", "item3").Err()
	if err != nil {
		panic(err)
	}

	// Retrieve the length of the list.
	length, err := rdb.LLen(context.Background(), "list2").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Length of list2:", length)

	// Retrieve an item from the list by index.
	item, err := rdb.LIndex(context.Background(), "list2", 1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Item at index 1 in list2:", item)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members with initial scores to a sorted set.
	err := rdb.ZAdd(context.Background(), "sortedset3", &redis.Z{
		Score:  1.0,
		Member: "member1",
	}, &redis.Z{
		Score:  2.0,
		Member: "member2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Increment the score of a member in the sorted set using ZINCRBY.
	newScore, err := rdb.ZIncrBy(context.Background(), "sortedset3", 2.5, "member1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("New score of member1 in sortedset3:", newScore)

	// Retrieve members with scores from the sorted set.
	vals, err := rdb.ZRangeWithScores(context.Background(), "sortedset3", 0, -1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members with scores in sortedset3:")
	for _, z := range vals {
		fmt.Printf("Member: %s, Score: %f\n", z.Member, z.Score)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Lua script to increment a counter.
	luaScript := `
        local current = redis.call('GET', KEYS[1])
        local amount = tonumber(ARGV[1])
        local new = current and tonumber(current) + amount or amount
        redis.call('SET', KEYS[1], new)
        return new
    `

	// Load the Lua script.
	script := redis.NewScript(luaScript)

	// Get the SHA1 digest of the Lua script.
	sha1, err := script.Load(context.Background(), rdb).Result()
	if err != nil {
		panic(err)
	}

	// Execute the Lua script using EVALSHA.
	val, err := rdb.EvalSha(context.Background(), sha1, []string{"counter"}, 5).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Counter value after Lua script with EVALSHA:", val)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set a key in Redis.
	err := rdb.Set(context.Background(), "oldkey", "value1", 0).Err()
	if err != nil {
		panic(err)
	}

	// Rename the key.
	err = rdb.Rename(context.Background(), "oldkey", "newkey").Err()
	if err != nil {
		panic(err)
	}

	// Retrieve the value of the new key.
	val, err := rdb.Get(context.Background(), "newkey").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Value of newkey:", val)

	// Attempt to retrieve the old key.
	val, err = rdb.Get(context.Background(), "oldkey").Result()
	if err != nil {
		if err == redis.Nil {
			fmt.Println("oldkey does not exist")
		} else {
			panic(err)
		}
	} else {
		fmt.Println("Value of oldkey:", val)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Set multiple fields in a hash.
	err := rdb.HSet(context.Background(), "hash4", map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Delete a field from the hash using HDEL.
	deletedCount, err := rdb.HDel(context.Background(), "hash4", "field1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Deleted fields count:", deletedCount)

	// Check if the deleted field exists.
	exists, err := rdb.HExists(context.Background(), "hash4", "field1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Field1 exists in hash4:", exists)
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members to a sorted set.
	err := rdb.ZAdd(context.Background(), "sortedset4", &redis.Z{
		Score:  1.0,
		Member: "member1",
	}, &redis.Z{
		Score:  2.0,
		Member: "member2",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Remove a member from the sorted set using ZREM.
	removedCount, err := rdb.ZRem(context.Background(), "sortedset4", "member1").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Removed members count:", removedCount)

	// Retrieve all members of the sorted set.
	vals, err := rdb.ZRange(context.Background(), "sortedset4", 0, -1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members of sortedset4 after removal:")
	for _, member := range vals {
		fmt.Println(member)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members to two different sets.
	err := rdb.SAdd(context.Background(), "set2", "member1", "member2", "member3").Err()
	if err != nil {
		panic(err)
	}
	err = rdb.SAdd(context.Background(), "set3", "member2", "member3", "member4").Err()
	if err != nil {
		panic(err)
	}

	// Calculate the difference between two sets using SDIFF.
	diff, err := rdb.SDiff(context.Background(), "set2", "set3").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Difference between set2 and set3:")
	for _, member := range diff {
		fmt.Println(member)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members to two different sets.
	err := rdb.SAdd(context.Background(), "set4", "member1", "member2", "member3").Err()
	if err != nil {
		panic(err)
	}
	err = rdb.SAdd(context.Background(), "set5", "member2", "member3", "member4").Err()
	if err != nil {
		panic(err)
	}

	// Calculate the intersection of two sets and store the result using SINTERSTORE.
	intersectCount, err := rdb.SInterStore(context.Background(), "set_intersection", "set4", "set5").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Intersection members count:", intersectCount)

	// Retrieve all members of the intersection set.
	vals, err := rdb.SMembers(context.Background(), "set_intersection").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members of set_intersection:")
	for _, member := range vals {
		fmt.Println(member)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members to two different sets.
	err := rdb.SAdd(context.Background(), "set6", "member1", "member2", "member3").Err()
	if err != nil {
		panic(err)
	}
	err = rdb.SAdd(context.Background(), "set7", "member2", "member3", "member4").Err()
	if err != nil {
		panic(err)
	}

	// Calculate the union of two sets and store the result using SUNIONSTORE.
	unionCount, err := rdb.SUnionStore(context.Background(), "set_union", "set6", "set7").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Union members count:", unionCount)

	// Retrieve all members of the union set.
	vals, err := rdb.SMembers(context.Background(), "set_union").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members of set_union:")
	for _, member := range vals {
		fmt.Println(member)
	}
}





package main

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
)

func main() {
	// Connect to Redis.
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
		DB:   0,                // Use default DB
	})

	// Add members with scores to a sorted set.
	err := rdb.ZAdd(context.Background(), "sortedset5", &redis.Z{
		Score:  1.0,
		Member: "member1",
	}, &redis.Z{
		Score:  2.0,
		Member: "member2",
	}, &redis.Z{
		Score:  3.0,
		Member: "member3",
	}).Err()
	if err != nil {
		panic(err)
	}

	// Retrieve members in reverse order from the sorted set using ZREVRANGE.
	vals, err := rdb.ZRevRange(context.Background(), "sortedset5", 0, -1).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Members of sortedset5 in reverse order:")
	for _, member := range vals {
		fmt.Println(member)
	}
}










// Example 1: Connecting to a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// Define your database connection string
const (
	host     = "localhost"
	port     = 5432
	user     = "your_username"
	password = "your_password"
	dbname   = "your_database"
)

func main() {
	connStr := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Ping the database to check if the connection is successful
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to PostgreSQL database!")
}





// Example 2: Querying data from a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	rows, err := db.QueryContext(context.Background(), "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 3: Inserting data into a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	username := "newuser"
	email := "newuser@example.com"

	_, err := db.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("New user inserted successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 4: Updating data in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	newUsername := "updateduser"
	userID := 1

	_, err := db.ExecContext(context.Background(), "UPDATE users SET username = $1 WHERE id = $2", newUsername, userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User updated successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 5: Deleting data from a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	userID := 1

	_, err := db.ExecContext(context.Background(), "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User deleted successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 6: Executing transactions in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	// Example of a transaction with two SQL operations
	username := "transactionuser"
	email := "transactionuser@example.com"

	// Insert operation inside transaction
	_, err = tx.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	// Another operation inside the same transaction
	_, err = tx.ExecContext(context.Background(), "UPDATE users SET email = $1 WHERE username = $2", "newemail@example.com", username)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction executed successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 7: Using prepared statements in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	stmt, err := db.PrepareContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	// Example of inserting multiple users using prepared statements
	users := []struct {
		Username string
		Email    string
	}{
		{"user1", "user1@example.com"},
		{"user2", "user2@example.com"},
		{"user3", "user3@example.com"},
	}

	for _, user := range users {
		_, err := stmt.ExecContext(context.Background(), user.Username, user.Email)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("Users inserted using prepared statements!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 8: Handling errors in SQL operations using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	username := "nonexistentuser"

	// Example of handling errors when querying for a single user
	var email string
	err := db.QueryRowContext(context.Background(), "SELECT email FROM users WHERE username = $1", username).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("User '%s' not found.\n", username)
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("Email of user '%s' is '%s'.\n", username, email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 9: Querying specific columns from a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID    int
	Name  string
	Email string
}

func main() {
	db := connectDB()

	rows, err := db.QueryContext(context.Background(), "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Name: %s, Email: %s\n", user.ID, user.Name, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 10: Using contexts in PostgreSQL queries with sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type User struct {
	ID    int
	Name  string
	Email string
}

func main() {
	db := connectDB()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Name, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Name: %s, Email: %s\n", user.ID, user.Name, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 11: Querying data with WHERE clause in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	username := "example_user"

	var user User
	err := db.QueryRowContext(context.Background(), "SELECT id, username, email FROM users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("No user found with username '%s'.\n", username)
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("User found: ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 12: Using transactions with error handling in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	username := "newuser"
	email := "newuser@example.com"

	_, err = tx.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	_, err = tx.ExecContext(context.Background(), "UPDATE users SET email = $1 WHERE username = $2", "updatedemail@example.com", username)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction executed successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 13: Deleting data using prepared statements in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	userID := 1

	stmt, err := db.PrepareContext(context.Background(), "DELETE FROM users WHERE id = $1")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(context.Background(), userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User deleted successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 14: Inserting data with error checking in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	username := "newuser"
	email := "newuser@example.com"

	result, err := db.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		log.Fatal(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Inserted %d rows successfully!\n", rowsAffected)
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 15: Updating data using named parameters in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	userID := 1
	newEmail := "updateduser@example.com"

	_, err := db.ExecContext(context.Background(), "UPDATE users SET email = $1 WHERE id = $2", newEmail, userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("User updated successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 16: Querying data using LIKE operator in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	likePattern := "%example%"

	rows, err := db.QueryContext(context.Background(), "SELECT id, username, email FROM users WHERE username LIKE $1", likePattern)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users matching pattern:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 17: Handling errors in transactions in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	username := "newuser"
	email := "newuser@example.com"

	_, err = tx.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	// Intentionally wrong column name to force an error
	_, err = tx.ExecContext(context.Background(), "UPDATE users SET invalid_column = $1 WHERE username = $2", "updatedemail@example.com", username)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction executed successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 18: Using QueryRow with context in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	userID := 1

	var user User
	err := db.QueryRowContext(context.Background(), "SELECT id, username, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("No user found with ID %d.\n", userID)
		} else {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("User found: ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 19: Using named returns in queries in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int    `db:"id"`
	Username string `db:"username"`
	Email    string `db:"email"`
}

func main() {
	db := connectDB()

	rows, err := db.QueryContext(context.Background(), "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 20: Using timeouts in queries in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 21: Batch inserting data into a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of batch inserting multiple users
	users := []User{
		{Username: "user1", Email: "user1@example.com"},
		{Username: "user2", Email: "user2@example.com"},
		{Username: "user3", Email: "user3@example.com"},
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	stmt, err := tx.PrepareContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)")
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}
	defer stmt.Close()

	for _, user := range users {
		_, err := stmt.ExecContext(context.Background(), user.Username, user.Email)
		if err != nil {
			tx.Rollback()
			log.Fatal(err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Batch insert completed successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 22: Handling NULL values in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username sql.NullString
	Email    sql.NullString
}

func main() {
	db := connectDB()

	rows, err := db.QueryContext(context.Background(), "SELECT id, username, email FROM users")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		if user.Username.Valid && user.Email.Valid {
			fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username.String, user.Email.String)
		} else {
			fmt.Printf("ID: %d, Username: NULL, Email: NULL\n", user.ID)
		}
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 23: Using LastInsertId in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	username := "newuser"
	email := "newuser@example.com"

	var userID int

	err := db.QueryRowContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id", username, email).Scan(&userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("New user inserted with ID: %d\n", userID)
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 24: Querying data using IN operator in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	userIDs := []int{1, 2, 3}

	// Prepare the query with placeholders for user IDs
	query := fmt.Sprintf("SELECT id, username, email FROM users WHERE id IN (%s)", strings.Trim(strings.Repeat("?, ", len(userIDs)), ", "))
	args := make([]interface{}, len(userIDs))
	for i, id := range userIDs {
		args[i] = id
	}

	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 25: Using subqueries in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of using subquery to fetch data
	query := `
		SELECT id, username, email
		FROM users
		WHERE id IN (
			SELECT user_id FROM posts WHERE category = 'tech'
		)
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users who posted in 'tech' category:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 26: Using EXISTS clause in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of using EXISTS clause
	query := `
		SELECT id, username, email
		FROM users u
		WHERE EXISTS (
			SELECT 1 FROM posts p WHERE p.user_id = u.id
		)
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users who have posted at least once:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 27: Using GROUP BY and HAVING clauses in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type UserStats struct {
	Username string
	Count    int
}

func main() {
	db := connectDB()

	// Example of using GROUP BY and HAVING clauses
	query := `
		SELECT username, COUNT(*) AS count
		FROM posts
		GROUP BY username
		HAVING COUNT(*) >= 3
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var userStats []UserStats
	for rows.Next() {
		var stats UserStats
		err := rows.Scan(&stats.Username, &stats.Count)
		if err != nil {
			log.Fatal(err)
		}
		userStats = append(userStats, stats)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users with at least 3 posts:")
	for _, stats := range userStats {
		fmt.Printf("Username: %s, Count: %d\n", stats.Username, stats.Count)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 28: Using ORDER BY and LIMIT clauses in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of using ORDER BY and LIMIT clauses
	query := `
		SELECT id, username, email
		FROM users
		ORDER BY id DESC
		LIMIT 5
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Latest 5 users:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 29: Using OFFSET and FETCH clauses in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of using OFFSET and FETCH clauses
	query := `
		SELECT id, username, email
		FROM users
		ORDER BY id ASC
		OFFSET 5
		FETCH FIRST 5 ROWS ONLY
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users from 6 to 10:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s\n", user.ID, user.Username, user.Email)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 30: Using joins in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
	Role     string
}

func main() {
	db := connectDB()

	// Example of using INNER JOIN
	query := `
		SELECT u.id, u.username, u.email, r.role_name
		FROM users u
		INNER JOIN roles r ON u.role_id = r.id
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Users with roles:")
	for _, user := range users {
		fmt.Printf("ID: %d, Username: %s, Email: %s, Role: %s\n", user.ID, user.Username, user.Email, user.Role)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 31: Using transactions with rollback in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of transaction with rollback on error
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	// Inserting a user
	username := "newuser"
	email := "newuser@example.com"
	_, err = tx.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", username, email)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	// Simulating an error that triggers rollback
	_, err = tx.ExecContext(context.Background(), "INSERT INTO non_existing_table (column1) VALUES ($1)", 123)
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction committed successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 32: Using conditional updates in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of conditional update based on a condition
	username := "existinguser"
	newEmail := "updatedemail@example.com"
	result, err := db.ExecContext(context.Background(), "UPDATE users SET email = $1 WHERE username = $2 AND email != $1", newEmail, username)
	if err != nil {
		log.Fatal(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Updated %d rows\n", rowsAffected)
}





// Example 33: Using subtransactions in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of using subtransactions
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	// Outer transaction
	_, err = tx.ExecContext(context.Background(), "INSERT INTO users (username, email) VALUES ($1, $2)", "user1", "user1@example.com")
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	// Inner transaction
	savepoint := "savepoint1"
	_, err = tx.ExecContext(context.Background(), fmt.Sprintf("SAVEPOINT %s", savepoint))
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	// Rollback inner transaction
	_, err = tx.ExecContext(context.Background(), fmt.Sprintf("ROLLBACK TO SAVEPOINT %s", savepoint))
	if err != nil {
		tx.Rollback()
		log.Fatal(err)
	}

	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction with subtransaction committed successfully!")
}





// Example 34: Using Common Table Expressions (CTE) in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Employee struct {
	ID        int
	FirstName string
	LastName  string
	ManagerID int
}

func main() {
	db := connectDB()

	// Example of using Common Table Expressions (CTE)
	query := `
		WITH RECURSIVE EmpPath AS (
			SELECT id, first_name, last_name, manager_id
			FROM employees
			WHERE id = $1
			UNION ALL
			SELECT e.id, e.first_name, e.last_name, e.manager_id
			FROM employees e
			JOIN EmpPath ep ON e.id = ep.manager_id
		)
		SELECT id, first_name, last_name, manager_id
		FROM EmpPath;
	`

	rows, err := db.QueryContext(context.Background(), query, 1)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		err := rows.Scan(&emp.ID, &emp.FirstName, &emp.LastName, &emp.ManagerID)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, emp)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Employee hierarchy:")
	for _, emp := range employees {
		fmt.Printf("ID: %d, Name: %s %s, ManagerID: %d\n", emp.ID, emp.FirstName, emp.LastName, emp.ManagerID)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 35: Using window functions in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Employee struct {
	ID        int
	FirstName string
	LastName  string
	Salary    int
}

func main() {
	db := connectDB()

	// Example of using window functions
	query := `
		SELECT id, first_name, last_name, salary,
		       RANK() OVER (ORDER BY salary DESC) AS salary_rank
		FROM employees;
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		err := rows.Scan(&emp.ID, &emp.FirstName, &emp.LastName, &emp.Salary)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, emp)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Employees ranked by salary:")
	for _, emp := range employees {
		fmt.Printf("ID: %d, Name: %s %s, Salary: %d, Rank: %d\n", emp.ID, emp.FirstName, emp.LastName, emp.Salary, emp.SalaryRank)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 36: Handling JSON data in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Price int    `json:"price"`
}

func main() {
	db := connectDB()

	// Example of handling JSON data
	query := `
		SELECT id, name, price
		FROM products
		WHERE details->>'category' = $1
	`

	category := "electronics"
	rows, err := db.QueryContext(context.Background(), query, category)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price)
		if err != nil {
			log.Fatal(err)
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Products in category '%s':\n", category)
	for _, p := range products {
		fmt.Printf("ID: %d, Name: %s, Price: %d\n", p.ID, p.Name, p.Price)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 37: Using stored procedures in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	db := connectDB()

	// Example of calling a stored procedure
	var userID int
	username := "existinguser"
	email := "updatedemail@example.com"

	err := db.QueryRowContext(context.Background(), "CALL update_user($1, $2, $3)", username, email, &userID).Scan(&userID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("User updated with ID: %d\n", userID)
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 38: Using arrays in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of using arrays in a query
	categories := []string{"electronics", "clothing", "books"}

	// Generate the placeholder string for array elements
	var placeholders []string
	for i := range categories {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
	}
	placeholderStr := strings.Join(placeholders, ",")

	query := fmt.Sprintf(`
		SELECT id, name, price
		FROM products
		WHERE category = ANY(ARRAY[%s])
	`, placeholderStr)

	args := make([]interface{}, len(categories))
	for i, category := range categories {
		args[i] = category
	}

	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price)
		if err != nil {
			log.Fatal(err)
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Products in categories:", categories)
	for _, p := range products {
		fmt.Printf("ID: %d, Name: %s, Price: %d\n", p.ID, p.Name, p.Price)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 39: Using conditional aggregates in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Order struct {
	ID       int
	Customer string
	Total    float64
}

func main() {
	db := connectDB()

	// Example of using conditional aggregates
	query := `
		SELECT id, customer, SUM(CASE WHEN status = 'completed' THEN total ELSE 0 END) AS total_completed
		FROM orders
		GROUP BY id, customer
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var orders []Order
	for rows.Next() {
		var order Order
		err := rows.Scan(&order.ID, &order.Customer, &order.Total)
		if err != nil {
			log.Fatal(err)
		}
		orders = append(orders, order)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Order totals:")
	for _, o := range orders {
		fmt.Printf("ID: %d, Customer: %s, Total Completed: %.2f\n", o.ID, o.Customer, o.Total)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 40: Using recursive queries in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Employee struct {
	ID        int
	FirstName string
	LastName  string
	ManagerID sql.NullInt64
}

func main() {
	db := connectDB()

	// Example of using recursive queries
	query := `
		WITH RECURSIVE EmpPath AS (
			SELECT id, first_name, last_name, manager_id
			FROM employees
			WHERE id = $1
			UNION ALL
			SELECT e.id, e.first_name, e.last_name, e.manager_id
			FROM employees e
			JOIN EmpPath ep ON e.id = ep.manager_id
		)
		SELECT id, first_name, last_name, manager_id
		FROM EmpPath;
	`

	employeeID := 1
	rows, err := db.QueryContext(context.Background(), query, employeeID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		err := rows.Scan(&emp.ID, &emp.FirstName, &emp.LastName, &emp.ManagerID)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, emp)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Employee hierarchy:")
	for _, emp := range employees {
		fmt.Printf("ID: %d, Name: %s %s, ManagerID: %v\n", emp.ID, emp.FirstName, emp.LastName, emp.ManagerID)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 41: Using upsert (INSERT ... ON CONFLICT UPDATE) in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of upsert (INSERT ... ON CONFLICT UPDATE)
	product := Product{
		ID:    1,
		Name:  "Updated Product",
		Price: 100,
	}

	query := `
		INSERT INTO products (id, name, price)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE
		SET name = excluded.name, price = excluded.price
	`

	_, err := db.ExecContext(context.Background(), query, product.ID, product.Name, product.Price)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Product upserted successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 42: Using window functions with PARTITION BY in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Employee struct {
	ID        int
	FirstName string
	LastName  string
	Department string
	Salary    int
	Rank      int
}

func main() {
	db := connectDB()

	// Example of using window functions with PARTITION BY
	query := `
		SELECT id, first_name, last_name, department, salary,
		       RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS rank
		FROM employees;
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var employees []Employee
	for rows.Next() {
		var emp Employee
		err := rows.Scan(&emp.ID, &emp.FirstName, &emp.LastName, &emp.Department, &emp.Salary, &emp.Rank)
		if err != nil {
			log.Fatal(err)
		}
		employees = append(employees, emp)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Employees ranked by salary within each department:")
	for _, emp := range employees {
		fmt.Printf("ID: %d, Name: %s %s, Department: %s, Salary: %d, Rank: %d\n", emp.ID, emp.FirstName, emp.LastName, emp.Department, emp.Salary, emp.Rank)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 43: Using triggers in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Employee struct {
	ID        int
	FirstName string
	LastName  string
}

func main() {
	db := connectDB()

	// Example of using triggers
	triggerName := "employee_audit_trigger"
	query := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION %s()
		RETURNS TRIGGER AS $$
		BEGIN
			-- Insert audit record on employee update
			INSERT INTO employee_audit (employee_id, action)
			VALUES (NEW.id, TG_OP);
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;

		CREATE TRIGGER %s
		AFTER UPDATE OF first_name, last_name ON employees
		FOR EACH ROW
		EXECUTE FUNCTION %s();
	`, triggerName, triggerName, triggerName)

	_, err := db.ExecContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Trigger created successfully!")
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 44: Using full-text search in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of using full-text search
	searchQuery := "apple"

	query := `
		SELECT id, name, price
		FROM products
		WHERE to_tsvector('english', name) @@ to_tsquery('english', $1)
	`

	rows, err := db.QueryContext(context.Background(), query, searchQuery)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price)
		if err != nil {
			log.Fatal(err)
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Products matching search query '%s':\n", searchQuery)
	for _, p := range products {
		fmt.Printf("ID: %d, Name: %s, Price: %d\n", p.ID, p.Name, p.Price)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 45: Using UUIDs in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type Product struct {
	ID    uuid.UUID
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of using UUIDs
	query := `
		SELECT id, name, price
		FROM products
		WHERE id = $1
	`

	productID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	row := db.QueryRowContext(context.Background(), query, productID)
	var product Product
	err := row.Scan(&product.ID, &product.Name, &product.Price)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Product found: ID=%s, Name=%s, Price=%d\n", product.ID.String(), product.Name, product.Price)
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 46: Using Common Table Expressions (CTE) for pagination in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of using Common Table Expressions (CTE) for pagination
	pageSize := 10
	pageNumber := 2

	query := fmt.Sprintf(`
		WITH paginated_products AS (
			SELECT id, name, price,
			       ROW_NUMBER() OVER (ORDER BY id) AS rownum
			FROM products
		)
		SELECT id, name, price
		FROM paginated_products
		WHERE rownum > $1 AND rownum <= $2
		ORDER BY rownum;
	`, (pageNumber-1)*pageSize, pageNumber*pageSize)

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var product Product
		err := rows.Scan(&product.ID, &product.Name, &product.Price)
		if err != nil {
			log.Fatal(err)
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Page %d of products (page size: %d):\n", pageNumber, pageSize)
	for _, p := range products {
		fmt.Printf("ID: %d, Name: %s, Price: %d\n", p.ID, p.Name, p.Price)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 47: Using PostGIS for spatial queries in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Location struct {
	ID       int
	Name     string
	Location string // Assuming PostGIS stores location as text for simplicity
}

func main() {
	db := connectDB()

	// Example of using PostGIS for spatial queries
	query := `
		SELECT id, name, location
		FROM locations
		WHERE ST_DWithin(location::geography, ST_GeogFromText('SRID=4326;POINT(10 20)'), 10000) -- Within 10km of point (10, 20)
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var locations []Location
	for rows.Next() {
		var loc Location
		err := rows.Scan(&loc.ID, &loc.Name, &loc.Location)
		if err != nil {
			log.Fatal(err)
		}
		locations = append(locations, loc)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Locations within 10km of point (10, 20):")
	for _, loc := range locations {
		fmt.Printf("ID: %d, Name: %s, Location: %s\n", loc.ID, loc.Name, loc.Location)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}






// Example 48: Using EXPLAIN for query analysis in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	db := connectDB()

	// Example of using EXPLAIN for query analysis
	query := `
		EXPLAIN SELECT id, name, price
		FROM products
		WHERE price > $1
	`

	explainQuery := "100"

	rows, err := db.QueryContext(context.Background(), query, explainQuery)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var explanation string
	for rows.Next() {
		err := rows.Scan(&explanation)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(explanation)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 49: Using database constraints (CHECK) in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Product struct {
	ID    int
	Name  string
	Price int
}

func main() {
	db := connectDB()

	// Example of using database constraints (CHECK)
	product := Product{
		ID:    1,
		Name:  "Valid Product",
		Price: 100,
	}

	query := `
		INSERT INTO products (id, name, price)
		VALUES ($1, $2, $3)
		RETURNING id
	`

	var productID int
	err := db.QueryRowContext(context.Background(), query, product.ID, product.Name, product.Price).Scan(&productID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Product inserted with ID: %d\n", productID)
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}





// Example 50: Using materialized views in a PostgreSQL database using sqlc

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type ProductSummary struct {
	Category   string
	TotalCount int
	AvgPrice   float64
}

func main() {
	db := connectDB()

	// Example of using materialized views
	query := `
		SELECT category, COUNT(*) AS total_count, AVG(price) AS avg_price
		FROM products
		GROUP BY category
	`

	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var summaries []ProductSummary
	for rows.Next() {
		var summary ProductSummary
		err := rows.Scan(&summary.Category, &summary.TotalCount, &summary.AvgPrice)
		if err != nil {
			log.Fatal(err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Product summaries:")
	for _, summary := range summaries {
		fmt.Printf("Category: %s, Total Count: %d, Avg Price: %.2f\n", summary.Category, summary.TotalCount, summary.AvgPrice)
	}
}

func connectDB() *sql.DB {
	connStr := "postgres://your_username:your_password@localhost/your_database?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}










/*
Example 1: Connect to a SQLite Database

Description:
This example demonstrates how to connect to a SQLite database using the go-sqlite3 library.

Dependencies:
Make sure you have imported the go-sqlite3 package:
    go get github.com/mattn/go-sqlite3

SQLite Database:
Assume you have a SQLite database named 'example.db' in the current directory.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    fmt.Println("Connected to SQLite database")
}





/*
Example 2: Create Table in SQLite Database

Description:
This example demonstrates how to create a table in a SQLite database using the go-sqlite3 library.

SQLite Database:
Assume you have connected to a SQLite database named 'example.db'.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create a new table
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            age INTEGER
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Table 'users' created successfully")
}





/*
Example 3: Insert Data into SQLite Table

Description:
This example demonstrates how to insert data into a SQLite table using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Prepare statement for inserting data
    stmt, err := db.Prepare("INSERT INTO users(name, age) VALUES(?, ?)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Insert data into the table
    _, err = stmt.Exec("Alice", 28)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data inserted successfully")
}





/*
Example 4: Query Data from SQLite Table

Description:
This example demonstrates how to query data from a SQLite table using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Query data from the table
    rows, err := db.Query("SELECT id, name, age FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id, age int
        var name string
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s, Age: %d\n", id, name, age)
    }

    fmt.Println("Query executed successfully")
}





/*
Example 5: Update Data in SQLite Table

Description:
This example demonstrates how to update data in a SQLite table using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Prepare statement for updating data
    stmt, err := db.Prepare("UPDATE users SET age=? WHERE name=?")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Update data in the table
    _, err = stmt.Exec(30, "Alice")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data updated successfully")
}





/*
Example 6: Delete Data from SQLite Table

Description:
This example demonstrates how to delete data from a SQLite table using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Prepare statement for deleting data
    stmt, err := db.Prepare("DELETE FROM users WHERE name=?")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Delete data from the table
    _, err = stmt.Exec("Alice")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data deleted successfully")
}





/*
Example 7: Transactions in SQLite

Description:
This example demonstrates how to use transactions in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Begin transaction
    tx, err := db.Begin()
    if err != nil {
        fmt.Println(err)
        return
    }

    // Perform operations within the transaction
    _, err = tx.Exec("INSERT INTO users(name, age) VALUES(?, ?)", "Bob", 32)
    if err != nil {
        tx.Rollback()
        fmt.Println(err)
        return
    }

    _, err = tx.Exec("DELETE FROM users WHERE name=?", "Alice")
    if err != nil {
        tx.Rollback()
        fmt.Println(err)
        return
    }

    // Commit the transaction
    err = tx.Commit()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Transaction committed successfully")
}





/*
Example 8: Prepared Statements in SQLite

Description:
This example demonstrates how to use prepared statements in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Prepare statement for querying data
    stmt, err := db.Prepare("SELECT id, name, age FROM users WHERE age > ?")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Query data using prepared statement
    rows, err := stmt.Query(30)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id, age int
        var name string
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s, Age: %d\n", id, name, age)
    }

    fmt.Println("Query executed successfully")
}





/*
Example 9: Error Handling in SQLite Operations

Description:
This example demonstrates error handling best practices when working with SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println("Error connecting to database:", err)
        return
    }
    defer db.Close()

    // Example of a query with error handling
    rows, err := db.Query("SELECT * FROM non_existing_table")
    if err != nil {
        fmt.Println("Error executing query:", err)
        return
    }
    defer rows.Close()

    fmt.Println("Query executed successfully")
}





/*
Example 10: Working with NULL Values in SQLite

Description:
This example demonstrates how to handle NULL values in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in Example 2).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Inserting NULL values into the table
    _, err = db.Exec("INSERT INTO users(name, age) VALUES(?, ?)", "Charlie", nil)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data with NULL value inserted successfully")
}





/*
Example 11: Check if Table Exists in SQLite Database

Description:
This example demonstrates how to check if a table exists in a SQLite database using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func tableExists(db *sql.DB, tableName string) (bool, error) {
    var exists bool
    query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
    err := db.QueryRow(query, tableName).Scan(&exists)
    if err != nil && err != sql.ErrNoRows {
        return false, err
    }
    return exists, nil
}

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Check if table 'users' exists
    exists, err := tableExists(db, "users")
    if err != nil {
        fmt.Println(err)
        return
    }

    if exists {
        fmt.Println("Table 'users' exists")
    } else {
        fmt.Println("Table 'users' does not exist")
    }
}





/*
Example 12: Drop Table in SQLite Database

Description:
This example demonstrates how to drop (delete) a table from a SQLite database using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Drop (delete) the table 'users'
    _, err = db.Exec("DROP TABLE IF EXISTS users")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Table 'users' dropped successfully")
}





/*
Example 13: Use Transactions for Bulk Insertion

Description:
This example demonstrates how to use transactions for bulk insertion into a SQLite database using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Begin transaction
    tx, err := db.Begin()
    if err != nil {
        fmt.Println(err)
        return
    }

    // Prepare statement for bulk insertion
    stmt, err := tx.Prepare("INSERT INTO users(name, age) VALUES(?, ?)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Example data for bulk insertion
    users := []struct {
        Name string
        Age  int
    }{
        {"David", 35},
        {"Emma", 27},
        {"Frank", 40},
    }

    // Insert data using transaction and prepared statement
    for _, user := range users {
        _, err = stmt.Exec(user.Name, user.Age)
        if err != nil {
            tx.Rollback()
            fmt.Println(err)
            return
        }
    }

    // Commit the transaction
    err = tx.Commit()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Bulk insertion completed successfully")
}





/*
Example 14: Retrieve Last Insert ID in SQLite

Description:
This example demonstrates how to retrieve the last inserted row ID in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Insert a row into the table 'users'
    result, err := db.Exec("INSERT INTO users(name, age) VALUES(?, ?)", "Grace", 33)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Retrieve the last inserted ID
    lastID, err := result.LastInsertId()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("Last Inserted ID: %d\n", lastID)
}





/*
Example 15: Perform Aggregate Function in SQLite

Description:
This example demonstrates how to perform an aggregate function (COUNT) in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Perform COUNT aggregate function
    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("Total number of users: %d\n", count)
}





/*
Example 16: Handle Foreign Key Constraints in SQLite

Description:
This example demonstrates how to enable and handle foreign key constraints in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with tables 'users' and 'orders' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with foreign key constraints enabled
    db, err := sql.Open("sqlite3", "./example.db?_foreign_keys=1")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create tables with foreign key constraints
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            amount INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Tables 'users' and 'orders' created with foreign key constraints successfully")
}





/*
Example 17: Use Named Parameters in SQLite Queries

Description:
This example demonstrates how to use named parameters in SQLite queries using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Insert a row into the table 'users' using named parameters
    stmt, err := db.Prepare("INSERT INTO users(name, age) VALUES(:name, :age)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    // Example data for insertion
    user := map[string]interface{}{
        "name": "Sophia",
        "age":  30,
    }

    // Execute the named parameter query
    _, err = stmt.Exec(user)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data inserted successfully using named parameters")
}





/*
Example 18: Handle SQLite NULL Values with Scan

Description:
This example demonstrates how to handle SQLite NULL values when scanning rows using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

type User struct {
    ID   int
    Name string
    Age  sql.NullInt64
}

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Query data from the table 'users'
    rows, err := db.Query("SELECT id, name, age FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var user User
        err := rows.Scan(&user.ID, &user.Name, &user.Age)
        if err != nil {
            fmt.Println(err)
            return
        }
        // Check for NULL value
        if user.Age.Valid {
            fmt.Printf("ID: %d, Name: %s, Age: %d\n", user.ID, user.Name, user.Age.Int64)
        } else {
            fmt.Printf("ID: %d, Name: %s, Age: NULL\n", user.ID, user.Name)
        }
    }

    fmt.Println("Query executed successfully")
}





/*
Example 19: Use Context with SQLite Operations

Description:
This example demonstrates how to use context with SQLite operations using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

Note:
Using context is important for managing timeouts and cancellations in concurrent environments.

*/

package main

import (
    "context"
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Create a context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Connect to the SQLite database with context
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example query using context
    var name string
    err = db.QueryRowContext(ctx, "SELECT name FROM users WHERE id=?", 1).Scan(&name)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("Name retrieved using context: %s\n", name)
}





/*
Example 20: Handle SQLite Errors Gracefully

Description:
This example demonstrates how to handle SQLite errors gracefully using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./non_existing_db.db")
    if err != nil {
        fmt.Println("Error connecting to database:", err)
        return
    }
    defer db.Close()

    // Example of a query with error handling
    rows, err := db.Query("SELECT * FROM non_existing_table")
    if err != nil {
        fmt.Println("Error executing query:", err)
        return
    }
    defer rows.Close()

    fmt.Println("Query executed successfully")
}





/*
Example 21: Use SQLite Functions in Queries

Description:
This example demonstrates how to use SQLite built-in functions in queries using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example of using SQLite built-in function (UPPER) in query
    rows, err := db.Query("SELECT id, UPPER(name) FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var name string
        err := rows.Scan(&id, &name)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name (uppercase): %s\n", id, name)
    }

    fmt.Println("Query executed successfully")
}





/*
Example 22: Use SQLite Extensions with go-sqlite3

Description:
This example demonstrates how to use SQLite extensions with the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

Note:
SQLite supports extensions that can be loaded dynamically. This example shows the basic setup for using extensions.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Enable SQLite extension (e.g., JSON1)
    _, err = db.Exec("SELECT load_extension('./json1')")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Use the extension functions in queries
    rows, err := db.Query("SELECT json_object('name', name, 'age', age) FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var jsonResult string
        err := rows.Scan(&jsonResult)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("JSON Object:", jsonResult)
    }

    fmt.Println("Query executed successfully with extension")
}





/*
Example 23: Use SQLite Virtual Tables with go-sqlite3

Description:
This example demonstrates how to use SQLite virtual tables with the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
SQLite allows creating custom virtual tables using extensions or modules. This example uses FTS5 (Full-Text Search) as a virtual table.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create a virtual table using FTS5
    _, err = db.Exec("CREATE VIRTUAL TABLE IF NOT EXISTS documents USING fts5(id, content)")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Insert data into the virtual table
    _, err = db.Exec("INSERT INTO documents(id, content) VALUES(1, 'Example document content')")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Virtual table 'documents' created and data inserted successfully")
}





/*
Example 24: Use SQLite Encryption with go-sqlite3

Description:
This example demonstrates how to use SQLite encryption with the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' that requires encryption.

Note:
SQLite does not natively support encryption. This example shows how to use the SQLite Encryption Extension (SEE) which provides encryption support.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with encryption
    db, err := sql.Open("sqlite3", "./example.db?_cipher=SEE&key=your_encryption_key")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example query with encrypted database
    rows, err := db.Query("SELECT * FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var name string
        var age int
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s, Age: %d\n", id, name, age)
    }

    fmt.Println("Query executed successfully with encryption")
}





/*
Example 25: Use SQLite Backup API

Description:
This example demonstrates how to use the SQLite Backup API for database backup and restore operations using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with some data.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the source SQLite database
    sourceDB, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer sourceDB.Close()

    // Connect to the destination SQLite database (backup file)
    destDB, err := sql.Open("sqlite3", "./backup.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer destDB.Close()

    // Initialize the backup process
    backup := sourceDB.DB().Backup("main", destDB.DB(), "main")
    if backup == nil {
        fmt.Println("Backup initialization failed")
        return
    }
    defer backup.Close()

    // Perform the backup operation
    _, err = backup.Step(-1)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Database backup completed successfully")
}





/*
Example 26: Use SQLite WAL Mode

Description:
This example demonstrates how to enable and use Write-Ahead Logging (WAL) mode in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with WAL mode enabled
    db, err := sql.Open("sqlite3", "./example.db?_wal=journal")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example of querying data with WAL mode
    rows, err := db.Query("SELECT * FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var name string
        var age int
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s, Age: %d\n", id, name, age)
    }

    fmt.Println("Query executed successfully with WAL mode")
}





/*
Example 27: Use SQLite User-defined Functions (UDF)

Description:
This example demonstrates how to define and use user-defined functions (UDFs) in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    "strings"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Define a custom UDF (concatenate strings)
    _, err = db.Exec(`CREATE FUNCTION concat_ws(separator TEXT, strings TEXT) RETURNS TEXT AS
    '
    return strings.join(strings.split(strings, separator), separator)
    '
    LANGUAGE SQL`)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example query using the custom UDF
    rows, err := db.Query("SELECT concat_ws(',', name, age) AS concatenated FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var concatenated string
        err := rows.Scan(&concatenated)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Concatenated string:", concatenated)
    }

    fmt.Println("Query executed successfully with custom UDF")
}





/*
Example 28: Use SQLite Indexes

Description:
This example demonstrates how to create and use indexes in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create index on the 'name' column
    _, err = db.Exec("CREATE INDEX idx_name ON users(name)")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example query using the index
    rows, err := db.Query("SELECT * FROM users WHERE name=?", "Alice")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var name string
        var age int
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s, Age: %d\n", id, name, age)
    }

    fmt.Println("Query executed successfully using index")
}





/*
Example 29: Use SQLite Triggers

Description:
This example demonstrates how to create and use triggers in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create a trigger that inserts a row into a log table on INSERT into 'users'
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    _, err = db.Exec(`
        CREATE TRIGGER IF NOT EXISTS user_insert_trigger
        AFTER INSERT ON users
        BEGIN
            INSERT INTO user_logs(user_id, action) VALUES(NEW.id, 'inserted');
        END
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert a row into 'users' table
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Bob', 25)")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Trigger executed successfully")
}





/*
Example 30: Use SQLite Views

Description:
This example demonstrates how to create and use views in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create a view that selects specific columns from 'users'
    _, err = db.Exec("CREATE VIEW IF NOT EXISTS user_names AS SELECT id, name FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example query using the view
    rows, err := db.Query("SELECT * FROM user_names")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var name string
        err := rows.Scan(&id, &name)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Name: %s\n", id, name)
    }

    fmt.Println("Query executed successfully using view")
}





/*
Example 31: Use SQLite Full-Text Search (FTS5)

Description:
This example demonstrates how to use Full-Text Search (FTS5) in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a virtual table 'documents' created using FTS5.

Note:
FTS5 is a SQLite extension that provides an efficient way to search for text in a large collection of documents.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example query using FTS5 full-text search
    rows, err := db.Query("SELECT * FROM documents WHERE content MATCH 'example'")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var content string
        err := rows.Scan(&id, &content)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Content: %s\n", id, content)
    }

    fmt.Println("Query executed successfully using FTS5")
}





/*
Example 32: Use SQLite Transactions

Description:
This example demonstrates how to use transactions in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Begin transaction
    tx, err := db.Begin()
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert multiple rows in a transaction
    stmt, err := tx.Prepare("INSERT INTO users(name, age) VALUES(?, ?)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    users := []struct {
        Name string
        Age  int
    }{
        {"Alice", 30},
        {"Bob", 25},
        {"Charlie", 35},
    }

    for _, user := range users {
        _, err = stmt.Exec(user.Name, user.Age)
        if err != nil {
            fmt.Println(err)
            tx.Rollback() // Rollback the transaction on error
            return
        }
    }

    // Commit transaction
    err = tx.Commit()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Transaction executed successfully")
}





/*
Example 33: Use SQLite Foreign Keys

Description:
This example demonstrates how to use foreign keys in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with tables 'users' and 'orders' (as created in previous examples).

Note:
SQLite supports foreign key constraints that enforce referential integrity between tables.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with foreign key support enabled
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Enable foreign key support
    _, err = db.Exec("PRAGMA foreign_keys = ON")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Create 'orders' table with foreign key constraint
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert order with a user ID that does not exist (should fail due to foreign key constraint)
    _, err = db.Exec("INSERT INTO orders(user_id, amount) VALUES(100, 50.0)")
    if err != nil {
        fmt.Println("Error inserting order:", err)
        return
    }

    fmt.Println("Foreign key constraint enforced successfully")
}





/*
Example 34: Use SQLite Check Constraints

Description:
This example demonstrates how to use check constraints in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

Note:
SQLite allows defining check constraints to enforce data integrity rules on column values.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create 'users' table with a check constraint
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            age INTEGER CHECK (age >= 18) -- Check constraint: age must be >= 18
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert a user with an age that violates the check constraint
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Alice', 17)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        return
    }

    fmt.Println("Check constraint enforced successfully")
}





/*
Example 35: Use SQLite Savepoints

Description:
This example demonstrates how to use savepoints in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

Note:
Savepoints allow creating named points within transactions to facilitate partial rollback and nested transactions.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Begin transaction
    tx, err := db.Begin()
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert a user with a savepoint
    _, err = tx.Exec("INSERT INTO users(name, age) VALUES('Alice', 30)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        tx.RollbackTo("start") // Rollback to savepoint 'start' on error
        return
    }

    // Create a savepoint 'start'
    _, err = tx.Exec("SAVEPOINT start")
    if err != nil {
        fmt.Println("Error creating savepoint:", err)
        tx.Rollback()
        return
    }

    // Example: Insert another user
    _, err = tx.Exec("INSERT INTO users(name, age) VALUES('Bob', 25)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        tx.RollbackTo("start") // Rollback to savepoint 'start' on error
        return
    }

    // Commit transaction
    err = tx.Commit()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Transaction with savepoint executed successfully")
}





/*
Example 36: Use SQLite Journal Mode

Description:
This example demonstrates how to set and use different journal modes in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
SQLite supports different journal modes that affect how transactions are handled and data is written to disk.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with a specific journal mode
    db, err := sql.Open("sqlite3", "./example.db?_journal_mode=WAL")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Insert data into 'users' table with WAL journal mode
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Alice', 30)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        return
    }

    fmt.Println("Data inserted successfully using WAL journal mode")
}





/*
Example 37: Use SQLite Write-Ahead Logging (WAL)

Description:
This example demonstrates how to enable and use Write-Ahead Logging (WAL) in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
WAL mode in SQLite improves concurrency and performance by allowing multiple readers and one writer to access the database.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database with WAL mode enabled
    db, err := sql.Open("sqlite3", "./example.db?_journal_mode=WAL")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Insert data into 'users' table with WAL mode
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Bob', 25)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        return
    }

    fmt.Println("Data inserted successfully using WAL mode")
}





/*
Example 38: Use SQLite Memory Database

Description:
This example demonstrates how to use an in-memory SQLite database using the go-sqlite3 library.

SQLite Database:
No physical file is created for an in-memory database. It exists entirely in RAM.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to an in-memory SQLite database
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Create a table in the in-memory database
    _, err = db.Exec(`
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            age INTEGER
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Insert data into the in-memory database
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Alice', 30)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        return
    }

    fmt.Println("Data inserted successfully into in-memory database")
}





/*
Example 39: Use SQLite Vacuum

Description:
This example demonstrates how to use the VACUUM command in SQLite to rebuild the database file and improve performance.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
The VACUUM command reclaims unused disk space and defragments the database file.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Perform VACUUM operation
    _, err = db.Exec("VACUUM")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Database vacuumed successfully")
}





/*
Example 40: Use SQLite Encrypt

Description:
This example demonstrates how to use encryption with SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' that you want to encrypt.

Note:
Encryption with SQLite can be achieved using external tools or libraries that provide encryption extensions.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database (encrypted)
    db, err := sql.Open("sqlite3", "./example.db?_crypt=secret")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Insert data into encrypted database
    _, err = db.Exec("INSERT INTO users(name, age) VALUES('Alice', 30)")
    if err != nil {
        fmt.Println("Error inserting user:", err)
        return
    }

    fmt.Println("Data inserted successfully into encrypted database")
}





/*
Example 41: Use SQLite Analyze

Description:
This example demonstrates how to use the ANALYZE command in SQLite to gather statistics for query optimization.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
The ANALYZE command collects statistics about the distribution of key values in tables, which helps the query planner make better decisions.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Perform ANALYZE operation
    _, err = db.Exec("ANALYZE")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("ANALYZE operation completed successfully")
}





/*
Example 42: Use SQLite Online Backup

Description:
This example demonstrates how to perform an online backup of a SQLite database using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
Online backup in SQLite allows you to make a copy of the database while it is still being accessed and modified.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Open the source SQLite database (to be backed up)
    sourceDB, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer sourceDB.Close()

    // Open the destination SQLite database (backup file)
    destDB, err := sql.Open("sqlite3", "./backup.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer destDB.Close()

    // Begin the online backup process
    _, err = destDB.Exec("ATTACH DATABASE './backup.db' AS backup")
    if err != nil {
        fmt.Println(err)
        return
    }
    _, err = destDB.Exec("SELECT sqlcipher_export('backup')")
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Online backup completed successfully")
}





/*
Example 43: Use SQLite Export CSV

Description:
This example demonstrates how to export data from a SQLite table to a CSV file using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "encoding/csv"
    "fmt"
    "os"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Query the data to export
    rows, err := db.Query("SELECT * FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Create a CSV file
    file, err := os.Create("users.csv")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()

    // Create a CSV writer
    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Iterate over the rows and write to CSV
    for rows.Next() {
        var id int
        var name string
        var age int
        err := rows.Scan(&id, &name, &age)
        if err != nil {
            fmt.Println(err)
            return
        }

        err = writer.Write([]string{fmt.Sprintf("%d", id), name, fmt.Sprintf("%d", age)})
        if err != nil {
            fmt.Println(err)
            return
        }
    }

    fmt.Println("Data exported to CSV successfully")
}





/*
Example 44: Use SQLite Import CSV

Description:
This example demonstrates how to import data from a CSV file into a SQLite table using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' where you want to import data into a table 'imported_users'.

Note:
Ensure the CSV file ('users.csv') exists and contains valid data.

*/

package main

import (
    "database/sql"
    "encoding/csv"
    "fmt"
    "os"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Create a table to import CSV data
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS imported_users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            age INTEGER
        )
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Open the CSV file
    file, err := os.Open("users.csv")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()

    // Create a CSV reader
    reader := csv.NewReader(file)

    // Read and insert each record into the database
    records, err := reader.ReadAll()
    if err != nil {
        fmt.Println(err)
        return
    }

    tx, err := db.Begin()
    if err != nil {
        fmt.Println(err)
        return
    }

    stmt, err := tx.Prepare("INSERT INTO imported_users(name, age) VALUES(?, ?)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer stmt.Close()

    for _, record := range records {
        _, err = stmt.Exec(record[1], record[2]) // Assuming the CSV has no header row
        if err != nil {
            fmt.Println(err)
            tx.Rollback()
            return
        }
    }

    // Commit the transaction
    err = tx.Commit()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Data imported from CSV successfully")
}





/*
Example 45: Use SQLite JSON Extension

Description:
This example demonstrates how to use the JSON1 extension in SQLite for JSON processing using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'json_data' (as created in previous examples).

Note:
The JSON1 extension provides functions and operators for working with JSON data stored in SQLite columns.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Insert JSON data into the 'json_data' table
    _, err = db.Exec(`
        INSERT INTO json_data(data)
        VALUES('{"name": "Alice", "age": 30}')
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Query JSON data using JSON1 functions
    rows, err := db.Query("SELECT json_extract(data, '$.name') FROM json_data")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var name string
        err := rows.Scan(&name)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Name:", name)
    }

    fmt.Println("JSON data processed successfully using JSON1 extension")
}





/*
Example 46: Use SQLite Math Extension

Description:
This example demonstrates how to use the math extension in SQLite for mathematical computations using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'numbers' (as created in previous examples).

Note:
The math extension provides mathematical functions such as sin, cos, sqrt, etc., which can be used in SQL queries.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example: Insert numerical data into the 'numbers' table
    _, err = db.Exec(`
        INSERT INTO numbers(value)
        VALUES(25)
    `)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Query mathematical computation using math extension functions
    rows, err := db.Query("SELECT sqrt(value) FROM numbers")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var sqrtValue float64
        err := rows.Scan(&sqrtValue)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Square root:", sqrtValue)
    }

    fmt.Println("Mathematical computation performed successfully using math extension")
}





/*
Example 47: Use SQLite Full-Text Search Extension

Description:
This example demonstrates how to use the full-text search (FTS5) extension in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a virtual table 'documents' created using FTS5.

Note:
FTS5 is a SQLite extension that provides an efficient way to search for text in a large collection of documents.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Example query using FTS5 full-text search
    rows, err := db.Query("SELECT * FROM documents WHERE content MATCH 'example'")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Iterate over the rows
    for rows.Next() {
        var id int
        var content string
        err := rows.Scan(&id, &content)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Printf("ID: %d, Content: %s\n", id, content)
    }

    fmt.Println("Query executed successfully using FTS5")
}





/*
Example 48: Use SQLite User-Defined Functions (UDFs)

Description:
This example demonstrates how to define and use user-defined functions (UDFs) in SQLite using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
UDFs allow extending SQLite with custom functions written in Go or registered external functions.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

// Example UDF: Custom function to calculate the square of a number
func squareFunction(context *sql.Context, value float64) (float64, error) {
    return value * value, nil
}

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Register the UDF (User-Defined Function)
    err = db.RegisterFunc("square", squareFunction, true)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Example: Use the square UDF in a SQL query
    rows, err := db.Query("SELECT square(5.0)")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Read the result of the query
    for rows.Next() {
        var result float64
        err := rows.Scan(&result)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("Square result:", result)
    }

    fmt.Println("UDF executed successfully")
}





/*
Example 49: Use SQLite Backup API

Description:
This example demonstrates how to perform a SQLite database backup using the SQLite Backup API with the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db'.

Note:
The SQLite Backup API provides a way to create a backup of a database file, even while it is being used.

*/

package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Open the source SQLite database (to be backed up)
    sourceDB, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer sourceDB.Close()

    // Open the destination SQLite database (backup file)
    destDB, err := sql.Open("sqlite3", "./backup.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer destDB.Close()

    // Initialize the SQLite Backup object
    backup := sqlite3.BackupInit(destDB, "main", sourceDB, "main")
    if backup == nil {
        fmt.Println("Backup initialization failed")
        return
    }

    // Perform the backup operation
    _, err = backup.Step(-1)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Finish the backup process
    err = backup.Finish()
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("SQLite database backup completed successfully")
}





/*
Example 50: Use SQLite Export Table Schema

Description:
This example demonstrates how to export the schema of a SQLite table to a text file using the go-sqlite3 library.

SQLite Database:
Assume you have a SQLite database named 'example.db' with a table 'users' (as created in previous examples).

*/

package main

import (
    "database/sql"
    "fmt"
    "os"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Connect to the SQLite database
    db, err := sql.Open("sqlite3", "./example.db")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Query to fetch table schema
    rows, err := db.Query("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()

    // Read the schema definition
    var schema string
    if rows.Next() {
        err := rows.Scan(&schema)
        if err != nil {
            fmt.Println(err)
            return
        }
    } else {
        fmt.Println("Table not found")
        return
    }

    // Write schema to a file
    file, err := os.Create("users_schema.txt")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()

    _, err = file.WriteString(schema)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Table schema exported successfully")
}










// This code logs a formatted message indicating that the application "Example" is starting and specifies the version of Go used to build the binary.
package main

import (
	"log"
	"runtime"
)

const info = `
Application %s starting.
The binary was build by GO: %s`

func main() {
	log.Printf(info, "Example", runtime.Version())
}

// This code prints all command line arguments, the name of the binary, and each subsequent argument with its index.
package main

import (
	"fmt"
	"os"
)

func main() {

	args := os.Args

	// This call will print
	// all command line arguments.
	fmt.Println(args)

	// The first argument, zero item from array,
	// is the name of the called binary.
	programName := args[0]
	fmt.Printf("The binary name is: %s \n", programName)

	// The rest of the arguments could be naturally obtained
	// by omitting the first argument.
	otherArgs := args[1:]
	fmt.Println(otherArgs)

	for idx, arg := range otherArgs {
		fmt.Printf("Arg %d = %s \n", idx, arg)
	}

}


// This code defines and parses command line flags for retry count, log prefix, and an array, then logs retry attempts and the array using the specified log prefix.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

// Custom type needs to implement
// flag.Value interface to be able to
// use it in flag.Var function.
type ArrayValue []string

func (s *ArrayValue) String() string {
	return fmt.Sprintf("%v", *s)
}

func (a *ArrayValue) Set(s string) error {
	*a = strings.Split(s, ",")
	return nil
}

func main() {

	// Extracting flag values with methods returning pointers
	retry := flag.Int("retry", -1, "Defines max retry count")

	// Read the flag using the XXXVar function.
	// In this case the variable must be defined
	// prior to the flag.
	var logPrefix string
	flag.StringVar(&logPrefix, "prefix", "", "Logger prefix")

	var arr ArrayValue
	flag.Var(&arr, "array", "Input array to iterate through.")

	// Execute the flag.Parse function, to
	// read the flags to defined variables.
	// Without this call the flag
	// variables remain empty.
	flag.Parse()

	// Sample logic not related to flags
	logger := log.New(os.Stdout, logPrefix, log.Ldate)

	retryCount := 0
	for retryCount < *retry {
		logger.Println("Retrying connection")
		logger.Printf("Sending array %v\n", arr)
		retryCount++
	}
}



// This code sets an environment variable, retrieves its value (or a default if not set), logs the values, and then unsets the environment variable.
package main

import (
	"log"
	"os"
)

func main() {

	key := "DB_CONN"
	// Set the environmental variable.
	os.Setenv(key, "postgres://as:as@example.com/pg?sslmode=verify-full")

	val := GetEnvDefault(key, "postgres://as:as@localhost/pg?sslmode=verify-full")

	log.Println("The value is :" + val)

	// Unset the environmental variable.
	os.Unsetenv(key)

	val = GetEnvDefault(key, "postgres://as:as@127.0.0.1/pg?sslmode=verify-full")

	log.Println("The default value is :" + val)

}

// GetEnvDefault retrieves the value of the environment variable
// specified by key, or returns defVal if the variable is not set.
func GetEnvDefault(key, defVal string) string {
	val, ex := os.LookupEnv(key)
	if !ex {
		return defVal
	}
	return val
}

// This code looks up an environment variable and logs a message if it is not set, then prints the value of the environment variable.
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {

	key := "DB_CONN"
	connStr, ex := os.LookupEnv(key)
	if !ex {
		log.Printf("The env variable %s is not set.\n", key)
	}
	fmt.Println(connStr)
}

// This code retrieves the value of the "DB_CONN" environment variable and logs it.
package main

import (
	"log"
	"os"
)

func main() {
	connStr := os.Getenv("DB_CONN")
	log.Printf("Connection string: %s\n", connStr)
}


// This code prints the path to the current executable, resolves and prints its directory, and evaluates and prints any symbolic links in the directory path.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	// Path to executable file
	fmt.Println(ex)

	// Resolve the directory
	// of the executable
	exPath := filepath.Dir(ex)
	fmt.Println("Executable path :" + exPath)

	// Use EvalSymlinks to get
	// the real path.
	realPath, err := filepath.EvalSymlinks(exPath)
	if err != nil {
		panic(err)
	}
	fmt.Println("Symlink evaluated:" + realPath)
}

// This code retrieves the current process ID, runs the "ps" command to display process information, and prints the output.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func main() {

	// Get the current process ID.
	pid := os.Getpid()
	fmt.Printf("Process PID: %d \n", pid)

	// Execute the "ps" command to display process information for the current process.
	prc := exec.Command("ps", "-p", strconv.Itoa(pid), "-v")
	out, err := prc.Output()
	if err != nil {
		panic(err)
	}

	// Print the output of the "ps" command.
	fmt.Println(string(out))

}


// This code sets up signal handling to catch specific termination signals, prints corresponding messages, and exits with an appropriate status code.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	// Create the channel where the received
	// signal will be sent. The Notify
	// will not block when the signal
	// is sent and the channel is not ready.
	// So it is better to
	// create a buffered channel.
	sChan := make(chan os.Signal, 1)

	// Notify will catch the
	// given signals and send
	// the os.Signal value
	// through the sChan.
	signal.Notify(sChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGKILL)

	// Create a channel to wait until the
	// signal is handled.
	exitChan := make(chan int)
	go func() {
		signal := <-sChan
		switch signal {
		case syscall.SIGHUP:
			fmt.Println("The calling terminal has been closed")
			exitChan <- 0

		case syscall.SIGINT:
			fmt.Println("The process has been interrupted by CTRL+C")
			exitChan <- 1

		case syscall.SIGTERM:
			fmt.Println("kill SIGTERM was executed for process")
			exitChan <- 1

		case syscall.SIGKILL:
			fmt.Println("SIGKILL handler")
			exitChan <- 1

		case syscall.SIGQUIT:
			fmt.Println("kill SIGQUIT was executed for process")
			exitChan <- 1
		}
	}()

	code := <-exitChan
	os.Exit(code)
}

// This code executes the "ls -a" command to list all files, captures the output, and prints it if the command succeeds.
package main

import (
	"bytes"
	"fmt"
	"os/exec"
)

func main() {

	// Create a command to execute "ls -a"
	prc := exec.Command("ls", "-a")

	// Create a buffer to capture the command's output
	out := bytes.NewBuffer([]byte{})
	prc.Stdout = out

	// Start the command
	err := prc.Start()
	if err != nil {
		fmt.Println(err)
	}

	// Wait for the command to complete
	prc.Wait()

	// Check if the command executed successfully
	if prc.ProcessState.Success() {
		fmt.Println("Process run successfully with output:\n")
		fmt.Println(out.String())
	}
}

// This Go program executes the 'ls -a' command to list all files and directories in the current directory,
// captures the command's output into a buffer, and prints the output if the command executes successfully.
package main

import (
	"bytes"
	"fmt"
	"os/exec"
)

func main() {
	prc := exec.Command("ls", "-a")
	out := bytes.NewBuffer([]byte{})
	prc.Stdout = out

	err := prc.Run()
	if err != nil {
		fmt.Println(err)
	}

	if prc.ProcessState.Success() {
		fmt.Println("Process run successfully with output:\n")
		fmt.Println(out.String())
	}
}

// This program executes a platform-specific command ('timeout' on Windows, 'sleep' on other systems) for 1 second, then prints process information including PID, execution time in milliseconds, and success status.

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

func main() {

	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "timeout"
	} else {
		cmd = "sleep"
	}

	proc := exec.Command(cmd, "1")
	proc.Start()

	// Wait function will
	// wait till the process ends.
	proc.Wait()

	// After the process terminates
	// the *os.ProcessState contains
	// simple information
	// about the process run
	fmt.Printf("PID: %d\n", proc.ProcessState.Pid())
	fmt.Printf("Process took: %dms\n", proc.ProcessState.SystemTime()/time.Microsecond)
	fmt.Printf("Exited sucessfuly : %t\n", proc.ProcessState.Success())
}


// This program starts a platform-specific command ('timeout' on Windows, 'sleep' on other systems) for 1 second, then prints the process state and PID of the running process.
package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func main() {

	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "timeout"
	} else {
		cmd = "sleep"
	}
	proc := exec.Command(cmd, "1")
	proc.Start()

	// No process state is returned
	// till the process finish.
	fmt.Printf("Process state for running process: %v\n", proc.ProcessState)

	// The PID could be obtain
	// event for the running process
	fmt.Printf("PID of running process: %d\n\n", proc.Process.Pid)
}


// Executes a Go program "sample.go" using "go run" command, sends input via standard input and prints output from stdout until killed after 2 seconds.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"time"
)

func main() {
	cmd := []string{"go", "run", "sample.go"}

	// The command line tool
	// "ping" is executed for
	// 2 seconds
	proc := exec.Command(cmd[0], cmd[1], cmd[2])

	// The process input is obtained
	// in form of io.WriteCloser. The underlying
	// implementation use the os.Pipe
	stdin, _ := proc.StdinPipe()
	defer stdin.Close()

	// For debugging purposes we watch the
	// output of the executed process
	stdout, _ := proc.StdoutPipe()
	defer stdout.Close()

	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			fmt.Println("Program says:" + s.Text())
		}
	}()

	// Start the process
	proc.Start()

	// Now the the following lines
	// are written to child
	// process standard input
	fmt.Println("Writing input")
	io.WriteString(stdin, "Hello\n")
	io.WriteString(stdin, "Golang\n")
	io.WriteString(stdin, "is awesome\n")

	time.Sleep(time.Second * 2)

	proc.Process.Kill()

}


// This program demonstrates interprocess communication by executing "go run sample.go" command,
// sending multiple lines of input to the child process, and printing its responses until killed after 2 seconds.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"time"
)

func main() {
	cmd := []string{"go", "run", "sample.go"}

	// The command line tool "go run sample.go" is executed for 2 seconds
	proc := exec.Command(cmd[0], cmd[1], cmd[2])

	// The process input is obtained in the form of io.WriteCloser using os.Pipe
	stdin, _ := proc.StdinPipe()
	defer stdin.Close()

	// For capturing and printing output from the executed process
	stdout, _ := proc.StdoutPipe()
	defer stdout.Close()

	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			fmt.Println("Program says:" + s.Text())
		}
	}()

	// Start the process
	proc.Start()

	// Writing input lines to the child process standard input
	fmt.Println("Writing input")
	io.WriteString(stdin, "Hello\n")
	io.WriteString(stdin, "Golang\n")
	io.WriteString(stdin, "is awesome\n")

	// Allow 2 seconds for the process to run
	time.Sleep(time.Second * 2)

	// Kill the process
	proc.Process.Kill()
}


// This program demonstrates logging to a dynamically named file, manages resource cleanup with signals,
// and gracefully shuts down a goroutine writing logs until termination signals are received.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var writer *os.File

func main() {

	// The file is opened as
	// a log file to write into.
	// This way we represent the resources
	// allocation.
	var err error
	writer, err = os.OpenFile(fmt.Sprintf("test_%d.log", time.Now().Unix()), os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}

	// The code is running in a goroutine
	// independently. So in case the program is
	// terminated from outside, we need to
	// let the goroutine know via the closeChan
	closeChan := make(chan bool)
	go func() {
		for {
			time.Sleep(time.Second)
			select {
			case <-closeChan:
				log.Println("Goroutine closing")
				return
			default:
				log.Println("Writing to log")
				io.WriteString(writer, fmt.Sprintf("Logging access %s\n", time.Now().String()))
			}

		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT)

	// This is blocking read from
	// sigChan where the Notify function sends
	// the signal.
	<-sigChan

	// After the signal is received
	// all the code behind the read from channel could be
	// considered as a cleanup
	close(closeChan)
	releaseAllResources()
	fmt.Println("The application shut down gracefully")
}

func releaseAllResources() {
	io.WriteString(writer, "Application releasing all resources\n")
	writer.Close()
}


// This program demonstrates the use of functional options to configure a Client struct,
// allowing configuration from a JSON file and environmental variables, and prints the resulting configuration.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Client struct {
	consulIP   string
	connString string
}

func (c *Client) String() string {
	return fmt.Sprintf("ConsulIP: %s , Connection String: %s",
		c.consulIP, c.connString)
}

var defaultClient = Client{
	consulIP:   "localhost:9000",
	connString: "postgres://localhost:5432",
}

// ConfigFunc works as a type to be used
// in functional options
type ConfigFunc func(opt *Client)

// FromFile func returns the ConfigFunc
// type. So this way it could read the configuration
// from the json.
func FromFile(path string) ConfigFunc {
	return func(opt *Client) {
		f, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		decoder := json.NewDecoder(f)

		fop := struct {
			ConsulIP   string `json:"consul_ip"`
			ConnString string `json:"conn_string"`
		}{}
		err = decoder.Decode(&fop)
		if err != nil {
			panic(err)
		}
		opt.consulIP = fop.ConsulIP
		opt.connString = fop.ConnString
	}
}

// FromEnv reads the configuration
// from the environmental variables
// and combines them with existing ones.
func FromEnv() ConfigFunc {
	return func(opt *Client) {
		connStr, exist := os.LookupEnv("CONN_DB")
		if exist {
			opt.connString = connStr
		}
	}
}

func NewClient(opts ...ConfigFunc) *Client {
	client := defaultClient
	for _, val := range opts {
		val(&client)
	}
	return &client
}

func main() {
	client := NewClient(FromFile("config.json"), FromEnv())
	fmt.Println(client.String())
}


// This program demonstrates the usage of strings.Contains, strings.HasPrefix, and strings.HasSuffix
// functions to check if a reference string contains a substring, starts with a prefix, or ends with a suffix.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary had a little lamb"

func main() {

	lookFor := "lamb"
	contain := strings.Contains(refString, lookFor)
	fmt.Printf("The \"%s\" contains \"%s\": %t \n", refString, lookFor, contain)

	lookFor = "wolf"
	contain = strings.Contains(refString, lookFor)
	fmt.Printf("The \"%s\" contains \"%s\": %t \n", refString, lookFor, contain)

	startsWith := "Mary"
	starts := strings.HasPrefix(refString, startsWith)
	fmt.Printf("The \"%s\" starts with \"%s\": %t \n", refString, startsWith, starts)

	endWith := "lamb"
	ends := strings.HasSuffix(refString, endWith)
	fmt.Printf("The \"%s\" ends with \"%s\": %t \n", refString, endWith, ends)

}


// This program splits the constant string refString using the underscore character "_"
// as a delimiter and prints each split word along with its index.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary_had a little_lamb"

func main() {
	words := strings.Split(refString, "_")
	for idx, word := range words {
		fmt.Printf("Word %d is: %s\n", idx, word)
	}
}


// This program splits the constant string refString using the characters '*', ',', '%', and '_' as delimiters
// and prints each split word along with its index.
package main

import (
	"fmt"
	"regexp"
)

const refString = "Mary*had,a%little_lamb"

func main() {
	words := regexp.MustCompile("[*,%_]{1}").Split(refString, -1)
	for idx, word := range words {
		fmt.Printf("Word %d is: %s\n", idx, word)
	}
}



// This program splits the constant string refString using a custom split function defined by splitFunc,
// which checks if each rune in the string is '*', ',', '%', or '_',
// and prints each split word along with its index.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary*had,a%little_lamb"

func main() {
	// The splitFunc is called for each
	// rune in a string. If the rune
	// equals any of the characters '*', ',', '%', '_',
	// the refString is split.
	splitFunc := func(r rune) bool {
		return strings.ContainsRune("*%,_", r)
	}

	words := strings.FieldsFunc(refString, splitFunc)
	for idx, word := range words {
		fmt.Printf("Word %d is: %s\n", idx, word)
	}
}

// This program splits the constant string refString into words using whitespace characters as delimiters
// and prints each word along with its index.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary had	a little lamb"

func main() {
	words := strings.Fields(refString)
	for idx, word := range words {
		fmt.Printf("Word %d is: %s\n", idx, word)
	}
}


// This program constructs a SQL SELECT statement template with placeholders,
// joins an array of conditions refStringSlice using "AND" as a delimiter,
// and prints the formatted SELECT statement.
package main

import (
	"fmt"
	"strings"
)

const selectBase = "SELECT * FROM user WHERE %s "

var refStringSlice = []string{
	" FIRST_NAME = 'Jack' ",
	" INSURANCE_NO = 333444555 ",
	" EFFECTIVE_FROM = SYSDATE ",
}

func main() {
	sentence := strings.Join(refStringSlice, " AND ")
	fmt.Printf(selectBase+"\n", sentence)
}


// This program constructs a SQL WHERE clause by joining an array of conditions refStringSlice
// using a custom join function jF, which determines whether to use "AND" or "OR" based on the content of each condition.
package main

import (
	"fmt"
	"strings"
)

const selectBase = "SELECT * FROM user WHERE "

var refStringSlice = []string{
	" FIRST_NAME = 'Jack' ",
	" INSURANCE_NO = 333444555 ",
	" EFFECTIVE_FROM = SYSDATE ",
}

type JoinFunc func(piece string) string

func main() {
	jF := func(p string) string {
		if strings.Contains(p, "INSURANCE") {
			return "OR"
		}
		return "AND"
	}
	result := JoinWithFunc(refStringSlice, jF)
	fmt.Println(selectBase + result)
}

func JoinWithFunc(refStringSlice []string, joinFunc JoinFunc) string {
	concatenate := refStringSlice[0]
	for _, val := range refStringSlice[1:] {
		concatenate = concatenate + joinFunc(val) + val
	}
	return concatenate
}


// This program demonstrates efficient string concatenation by copying each string
// from the slice `strings` into a byte slice `bs` using the `copy` function,
// and then converting the byte slice back to a string for output.
package main

import (
	"fmt"
)

func main() {
	strings := []string{"This ", "is ", "even ", "more ", "performant "}

	bs := make([]byte, 100)
	bl := 0

	for _, val := range strings {
		bl += copy(bs[bl:], []byte(val))
	}

	fmt.Println(string(bs[:bl]))
}



// This program efficiently concatenates multiple strings from the slice `strings`
// into a single string using a bytes.Buffer to accumulate the result,
// demonstrating a more performant approach compared to direct string concatenation.
package main

import (
	"bytes"
	"fmt"
)

func main() {
	strings := []string{"This ", "is ", "even ", "more ", "performant "}
	buffer := bytes.Buffer{}
	for _, val := range strings {
		buffer.WriteString(val)
	}

	fmt.Println(buffer.String())
}

// This program demonstrates the usage of the tabwriter package
// to format and align columns of text, particularly for tabular data output.
package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func main() {
	w := tabwriter.NewWriter(os.Stdout, 15, 0, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "username\tfirstname\tlastname\t")
	fmt.Fprintln(w, "sohlich\tRadomir\tSohlich\t")
	fmt.Fprintln(w, "novak\tJohn\tSmith\t")
	w.Flush()
}


// This program demonstrates the usage of regular expressions
// to replace all substrings matching the pattern "l[a-z]+" in the constant refString
// with the string "replacement".
package main

import (
	"fmt"
	"regexp"
)

const refString = "Mary had a little lamb"

func main() {
	regex := regexp.MustCompile("l[a-z]+")
	out := regex.ReplaceAllString(refString, "replacement")
	fmt.Println(out)
}


// This program demonstrates the usage of strings.Replace function
// to replace all occurrences of "lamb" with "wolf" in the constant refString,
// and replace only the first two occurrences of "lamb" with "wolf" in the constant refStringTwo.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary had a little lamb"
const refStringTwo = "lamb lamb lamb lamb"

func main() {
	out := strings.Replace(refString, "lamb", "wolf", -1)
	fmt.Println(out)

	out = strings.Replace(refStringTwo, "lamb", "wolf", 2)
	fmt.Println(out)
}


// This program demonstrates the usage of strings.NewReplacer to create a custom string replacer,
// replacing occurrences of "lamb" with "wolf" and "Mary" with "Jack" in the constant refString.
package main

import (
	"fmt"
	"strings"
)

const refString = "Mary had a little lamb"

func main() {
	replacer := strings.NewReplacer("lamb", "wolf", "Mary", "Jack")
	out := replacer.Replace(refString)
	fmt.Println(out)
}



// This program demonstrates the usage of regular expressions to extract email addresses
// from the constant refString, using a simplified pattern matching approach.
package main

import (
	"fmt"
	"regexp"
)

const refString = `[{ "email": "email@example.com" "phone": 555467890},
{ "email": "other@domain.com" "phone": 555467890}]`

func main() {
	// This pattern is simplified for brevity
	emailRegexp := regexp.MustCompile("[a-zA-Z0-9]{1,}@[a-zA-Z0-9]{1,}\\.[a-z]{1,}")
	first := emailRegexp.FindString(refString)
	fmt.Println("First: ")
	fmt.Println(first)

	all := emailRegexp.FindAllString(refString, -1)
	fmt.Println("All: ")
	for _, val := range all {
		fmt.Println(val)
	}
}

// This program demonstrates reading and decoding a file encoded in Windows-1250 charset.
// It reads the file "win1250.txt", displays its content in its raw form,
// and then decodes it from Windows-1250 to Unicode using golang.org/x/text/encoding/charmap package.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

func main() {
	// Open windows-1250 encoded file.
	f, err := os.Open("win1250.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Read all content in raw form.
	b, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	content := string(b)

	fmt.Println("Without decode: " + content)

	// Decode to Unicode.
	decoder := charmap.Windows1250.NewDecoder()
	reader := decoder.Reader(strings.NewReader(content))
	b, err = ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decoded: " + string(b))
}


// This program demonstrates writing Unicode text "Gdańsk" to a file "out.txt"
// encoded in Windows-1250 charset using golang.org/x/text/encoding/charmap package.
package main

import (
	"io"
	"os"

	"golang.org/x/text/encoding/charmap"
)

func main() {
	f, err := os.OpenFile("out.txt", os.O_CREATE|os.O_RDWR, os.ModePerm|os.ModeAppend)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Encode Unicode to Windows-1250.
	encoder := charmap.Windows1250.NewEncoder()
	writer := encoder.Writer(f)
	io.WriteString(writer, "Gdańsk")
}

// This program demonstrates various string manipulations such as case conversion,
// matching case-insensitive strings, and converting snake_case to camelCase.
package main

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	email     = "ExamPle@domain.com"
	name      = "isaac newton"
	upc       = "upc"
	i         = "i"
	snakeCase = "first_name"
)

func main() {
	// Compare email case insensitively.
	input := "Example@domain.com"
	input = strings.ToLower(input)
	emailToCompare := strings.ToLower(email)
	matches := input == emailToCompare
	fmt.Printf("Email matches: %t\n", matches)

	// Convert to upper case.
	upcCode := strings.ToUpper(upc)
	fmt.Println("UPPER case: " + upcCode)

	// Convert to upper case and title case.
	str := "ǳ"
	fmt.Printf("%s in upper: %s and title: %s \n",
		str,
		strings.ToUpper(str),
		strings.ToTitle(str))

	// Compare ToTitle and ToTitleSpecial functions.
	title := strings.ToTitle(i)
	titleTurk := strings.ToTitleSpecial(unicode.TurkishCase, i)
	if title != titleTurk {
		fmt.Printf("ToTitle is different: %#U vs. %#U \n",
			title[0],
			[]rune(titleTurk)[0])
	}

	// Correct the case of a name.
	correctNameCase := strings.Title(name)
	fmt.Println("Corrected name: " + correctNameCase)

	// Convert snake_case to camelCase.
	firstNameCamel := toCamelCase(snakeCase)
	fmt.Println("Camel case: " + firstNameCamel)
}

func toCamelCase(input string) string {
	titleSpace := strings.Title(strings.Replace(input, "_", " ", -1))
	camel := strings.ReplaceAll(titleSpace, " ", "")
	return strings.ToLower(camel[:1]) + camel[1:]
}


// This program reads a CSV file, ignores lines starting with '#', and ensures each record has exactly 3 fields.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

func main() {
	// Open the CSV file.
	file, err := os.Open("data.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Create a CSV reader.
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = 3 // Ensure each record has exactly 3 fields.
	reader.Comment = '#'       // Ignore lines starting with '#'.

	// Read and print each record.
	for {
		record, err := reader.Read()
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Println(record)
	}
}



// This program reads a CSV file where the field delimiter is ';' instead of the default ','.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

func main() {
	// Open the CSV file.
	file, err := os.Open("data_uncommon.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Create a CSV reader with ';' as the delimiter.
	reader := csv.NewReader(file)
	reader.Comma = ';'

	// Read and print each record.
	for {
		record, err := reader.Read()
		if err != nil {
			fmt.Println(err)
			break
		}
		fmt.Println(record)
	}
}



// This program demonstrates various string manipulation operations such as trimming whitespace,
// replacing multiple spaces with a single space, and padding strings with spaces based on alignment.
package main

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	// Example of trimming leading and trailing whitespace.
	stringToTrim := "\t\t\n   Go \tis\t Awesome \t\t"
	trimResult := strings.TrimSpace(stringToTrim)
	fmt.Println("Trimmed:", trimResult)

	// Example of replacing multiple spaces with a single space.
	stringWithSpaces := "\t\t\n   Go \tis\n Awesome \t\t"
	r := regexp.MustCompile("\\s+")
	replace := r.ReplaceAllString(stringWithSpaces, " ")
	fmt.Println("Spaces replaced:", replace)

	// Examples of padding strings with spaces based on alignment.
	needSpace := "need space"
	fmt.Println("Center padded:", pad(needSpace, 14, "CENTER"))
	fmt.Println("Left padded:", pad(needSpace, 14, "LEFT"))
}

// pad function pads the input string with spaces to achieve the desired length and alignment.
func pad(input string, padLen int, align string) string {
	inputLen := len(input)

	if inputLen >= padLen {
		return input
	}

	repeat := padLen - inputLen
	var output string
	switch align {
	case "RIGHT":
		output = fmt.Sprintf("% "+strconv.Itoa(-padLen)+"s", input)
	case "LEFT":
		output = fmt.Sprintf("% "+strconv.Itoa(padLen)+"s", input)
	case "CENTER":
		bothRepeat := float64(repeat) / float64(2)
		left := int(math.Floor(bothRepeat)) + inputLen
		right := int(math.Ceil(bothRepeat))
		output = fmt.Sprintf("% "+strconv.Itoa(left)+"s% "+strconv.Itoa(right)+"s", input, "")
	}
	return output
}



// This program demonstrates functions for indenting and unindenting strings based on spaces and runes.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

func main() {
	// Example of indenting the text by prefixing with spaces.
	text := "Hi! Go is awesome."
	text = Indent(text, 6)
	fmt.Println("Indented:", text)

	// Example of unindenting the text by removing a specified number of leading spaces.
	text = Unindent(text, 3)
	fmt.Println("Unindented:", text)

	// Trying to unindent more than the current indent level won't affect the string.
	text = Unindent(text, 10)
	fmt.Println("Unindented beyond limit:", text)

	// Example of indenting the text by prefixing with a specified rune.
	text = IndentByRune(text, 10, '.')
	fmt.Println("Indented by rune:", text)
}

// Indent adds spaces to the beginning of the input string to achieve the desired indentation level.
func Indent(input string, indent int) string {
	padding := indent + len(input)
	return fmt.Sprintf("% "+strconv.Itoa(padding)+"s", input)
}

// Unindent removes a specified number of leading spaces from the input string.
// If the input is indented by fewer spaces than the specified indent, it removes all leading spaces.
func Unindent(input string, indent int) string {
	count := 0
	for _, val := range input {
		if unicode.IsSpace(val) {
			count++
		}
		if count == indent || !unicode.IsSpace(val) {
			break
		}
	}
	return input[count:]
}

// IndentByRune adds a specified rune at the beginning of the input string to achieve the desired indentation level.
func IndentByRune(input string, indent int, r rune) string {
	return strings.Repeat(string(r), indent) + input
}







// This code demonstrates how to parse string representations of different numeric types (decimal, hexadecimal, binary, and floating-point) into their respective numeric values using the strconv package.

package main

import (
	"fmt"
	"strconv"
)

const bin = "00001"
const hex = "2f"
const intString = "12"
const floatString = "12.3"

func main() {

	// Decimals
	res, err := strconv.Atoi(intString)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed integer: %d\n", res)

	// Parsing hexadecimals
	res64, err := strconv.ParseInt(hex, 16, 32)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed hexadecimal: %d\n", res64)

	// Parsing binary values
	resBin, err := strconv.ParseInt(bin, 2, 32)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed binary: %d\n", resBin)

	// Parsing floating points
	resFloat, err := strconv.ParseFloat(floatString, 32)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Parsed float: %.5f\n", resFloat)

}



// This code demonstrates the comparison of floating-point numbers using both float64 and big.Float types. It highlights the precision control with big.Float and its impact on comparison results.

package main

import (
	"fmt"
	"math/big"
)

var da float64 = 0.299999992
var db float64 = 0.299999991

var prec uint = 32
var prec2 uint = 16

func main() {

	fmt.Printf("Comparing float64 with '==' equals: %v\n", da == db)

	daB := big.NewFloat(da).SetPrec(prec)
	dbB := big.NewFloat(db).SetPrec(prec)

	fmt.Printf("A: %v \n", daB)
	fmt.Printf("B: %v \n", dbB)
	fmt.Printf("Comparing big.Float with precision: %d : %v\n", prec, daB.Cmp(dbB) == 0)

	daB = big.NewFloat(da).SetPrec(prec2)
	dbB = big.NewFloat(db).SetPrec(prec2)

	fmt.Printf("A: %v \n", daB)
	fmt.Printf("B: %v \n", dbB)
	fmt.Printf("Comparing big.Float with precision: %d : %v\n", prec2, daB.Cmp(dbB) == 0)

}



// This code demonstrates different methods for comparing floating-point numbers, including string formatting and numerical tolerance to handle precision limitations.

package main

import (
	"fmt"
	"math"
)

const da = 0.29999999999999998889776975374843459576368331909180
const db = 0.3

func main() {

	daStr := fmt.Sprintf("%.10f", da)
	dbStr := fmt.Sprintf("%.10f", db)

	// While formatting the number to string
	// it is rounded to 3.
	fmt.Printf("Strings %s = %s equals: %v \n", daStr, dbStr, dbStr == daStr)

	// Numbers are not equal
	fmt.Printf("Number equals: %v \n", db == da)

	// As the precision of float representation
	// is limited. For the float comparison it is
	// better to use comparison with some tolerance.
	fmt.Printf("Number equals with TOLERANCE: %v \n", Equals(da, db))

}

const TOLERANCE = 1e-8

// Equals compares the floating point numbers
// with tolerance 1e-8
func Equals(numA, numB float64) bool {
	delta := math.Abs(numA - numB)
	return delta < TOLERANCE
}



// This code demonstrates the difference between truncating a floating-point number to an integer and rounding it properly using a custom function.

package main

import (
	"fmt"
	"math"
)

var valA float64 = 3.55554444

func main() {

	// Bad assumption on rounding
	// the number by casting it to
	// integer.
	intVal := int(valA)
	fmt.Printf("Bad rounding by casting to int: %v\n", intVal)

	fRound := Round(valA)
	fmt.Printf("Rounding by custom function: %v\n", fRound)

}

// Round returns the nearest integer.
func Round(x float64) float64 {
	t := math.Trunc(x)
	if math.Abs(x-t) >= 0.5 {
		return t + math.Copysign(1, x)
	}
	return t
}



// This code demonstrates high-precision arithmetic using the math/big package to perform calculations on large floating-point numbers, including the calculation of a circle's circumference and basic arithmetic operations.

package main

import (
	"fmt"
	"math/big"
)

const PI = `3.14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196`
const diameter = 3.0
const precision = 400

func main() {

	pi, _ := new(big.Float).SetPrec(precision).SetString(PI)
	d := new(big.Float).SetPrec(precision).SetFloat64(diameter)

	circumference := new(big.Float).Mul(pi, d)

	pi64, _ := pi.Float64()
	fmt.Printf("Circumference big.Float = %.100f\n", circumference)
	fmt.Printf("Circumference float64   = %.100f\n", pi64*diameter)

	sum := new(big.Float).Add(pi, pi)
	fmt.Printf("Sum = %.100f\n", sum)

	diff := new(big.Float).Sub(pi, pi)
	fmt.Printf("Diff = %.100f\n", diff)

	quo := new(big.Float).Quo(pi, pi)
	fmt.Printf("Quotient = %.100f\n", quo)

}



// This code demonstrates various formatting options using fmt.Printf to print integers and floating-point numbers in different ways, including different bases, padding, and scientific notation.

package main

import (
	"fmt"
)

var integer int64 = 32500
var floatNum float64 = 22000.456

func main() {

	// Common way to print the decimal number
	fmt.Printf("%d \n", integer)

	// Always show the sign
	fmt.Printf("%+d \n", integer)

	// Print in other bases: x - 16, o - 8, b - 2, d - 10
	fmt.Printf("%x \n", integer)
	fmt.Printf("%#x \n", integer)

	// Padding with leading zeros
	fmt.Printf("%010d \n", integer)

	// Left padding with spaces
	fmt.Printf("% 10d \n", integer)

	// Right padding
	fmt.Printf("% -10d \n", integer)

	// Print floating point number
	fmt.Printf("%f \n", floatNum)

	// Floating point number with limited precision = 5
	fmt.Printf("%.5f \n", floatNum)

	// Floating point number in scientific notation
	fmt.Printf("%e \n", floatNum)

	// Floating point number in %e for large exponents or %f otherwise
	fmt.Printf("%g \n", floatNum)

}



// This code demonstrates formatting numbers according to different locales using the golang.org/x/text/message package.

package main

import (
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const num = 100000.5678

func main() {
	p := message.NewPrinter(language.English)
	p.Printf("%.2f \n", num)

	p = message.NewPrinter(language.German)
	p.Printf("%.2f \n", num)
}



// This code demonstrates converting integer values between different bases (binary, hexadecimal, octal, and decimal) using custom functions.

package main

import (
	"fmt"
	"strconv"
)

const bin = "10111"
const hex = "1A"
const oct = "12"
const dec = "10"

func main() {

	// Converts binary value into hex
	v, _ := ConvertInt(bin, 2, 16)
	fmt.Printf("Binary value %s converted to hex: %s\n", bin, v)

	// Converts hex value into dec
	v, _ = ConvertInt(hex, 16, 10)
	fmt.Printf("Hex value %s converted to dec: %s\n", hex, v)

	// Converts oct value into hex
	v, _ = ConvertInt(oct, 8, 16)
	fmt.Printf("Oct value %s converted to hex: %s\n", oct, v)

	// Converts dec value into oct
	v, _ = ConvertInt(dec, 10, 8)
	fmt.Printf("Dec value %s converted to oct: %s\n", dec, v)

	// Analogically, any other conversion could be done.

}

// ConvertInt converts the given string value of base to defined toBase.
func ConvertInt(val string, base, toBase int) (string, error) {
	i, err := strconv.ParseInt(val, base, 64)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(i, toBase), nil
}



// This code demonstrates handling pluralization and localization of messages using the golang.org/x/text/message package, customizing messages based on variable values and locale settings.

package main

import (
	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

func main() {

	// Set pluralization rules for the message "%d items to do" in English
	message.Set(language.English, "%d items to do",
		plural.Selectf(1, "%d",
			"=0", "no items to do",
			plural.One, "one item to do",
			"<100", "%[1]d items to do",
			plural.Other, "lot of items to do",
		))

	// Set pluralization rules for the message "The average is %.2f" in English
	message.Set(language.English, "The average is %.2f",
		plural.Selectf(1, "%.2f",
			"<1", "The average is zero",
			"=1", "The average is one",
			plural.Other, "The average is %[1]f ",
		))

	// Create a new printer for the English language
	prt := message.NewPrinter(language.English)

	// Print messages based on the set pluralization rules
	prt.Printf("%d items to do", 0)
	prt.Println()
	prt.Printf("%d items to do", 1)
	prt.Println()
	prt.Printf("%d items to do", 10)
	prt.Println()
	prt.Printf("%d items to do", 1000)
	prt.Println()

	prt.Printf("The average is %.2f", 0.8)
	prt.Println()
	prt.Printf("The average is %.2f", 1.0)
	prt.Println()
	prt.Printf("The average is %.2f", 10.0)
	prt.Println()

}



// This code demonstrates the generation of random numbers using both the math/rand package and crypto/rand package.
// It compares sequences generated by math/rand and ensures cryptographic random numbers from crypto/rand are distinct.

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
)

func main() {

	// Using math/rand package
	sec1 := rand.New(rand.NewSource(10))
	sec2 := rand.New(rand.NewSource(10))
	for i := 0; i < 5; i++ {
		rnd1 := sec1.Int()
		rnd2 := sec2.Int()
		if rnd1 != rnd2 {
			fmt.Println("Rand generated non-equal sequence")
			break
		} else {
			fmt.Printf("Math/Rand1: %d , Math/Rand2: %d\n", rnd1, rnd2)
		}
	}

	// Using crypto/rand package
	for i := 0; i < 5; i++ {
		safeNum := NewCryptoRand()
		safeNum2 := NewCryptoRand()
		if safeNum == safeNum2 {
			fmt.Println("Crypto generated equal numbers")
			break
		} else {
			fmt.Printf("Crypto/Rand1: %d , Crypto/Rand2: %d\n", safeNum, safeNum2)
		}
	}
}

// NewCryptoRand generates a random number using crypto/rand package.
func NewCryptoRand() int64 {
	safeNum, err := rand.Int(rand.Reader, big.NewInt(100234))
	if err != nil {
		panic(err)
	}
	return safeNum.Int64()
}



// This code demonstrates basic operations and functions related to complex numbers in Go.

package main

import (
	"fmt"
	"math/cmplx"
)

func main() {

	// Complex numbers are defined with real and imaginary parts as float64.
	a := complex(2, 3)

	fmt.Printf("Real part: %f \n", real(a))
	fmt.Printf("Imaginary part: %f \n", imag(a))

	b := complex(6, 4)

	// Basic arithmetic operations on complex numbers
	c := a - b
	fmt.Printf("Difference : %v\n", c)
	c = a + b
	fmt.Printf("Sum : %v\n", c)
	c = a * b
	fmt.Printf("Product : %v\n", c)
	c = a / b
	fmt.Printf("Quotient : %v\n", c)

	// Calculating conjugate of a complex number
	conjugate := cmplx.Conj(a)
	fmt.Println("Complex number a's conjugate : ", conjugate)

	// Calculating cosine of a complex number
	cos := cmplx.Cos(b)
	fmt.Println("Cosine of b : ", cos)

}



// This program demonstrates conversion between radians and degrees using both standalone functions and type methods in Go.

package main

import (
	"fmt"
	"math"
)

type Radian float64

func (rad Radian) ToDegrees() Degree {
	return Degree(float64(rad) * (180.0 / math.Pi))
}

func (rad Radian) Float64() float64 {
	return float64(rad)
}

type Degree float64

func (deg Degree) ToRadians() Radian {
	return Radian(float64(deg) * (math.Pi / 180.0))
}

func (deg Degree) Float64() float64 {
	return float64(deg)
}

func main() {

	// Using standalone functions for conversion
	val := radiansToDegrees(1)
	fmt.Printf("One radian is : %.4f degrees\n", val)

	val2 := degreesToRadians(val)
	fmt.Printf("%.4f degrees is %.4f rad\n", val, val2)

	// Using type methods for conversion
	val = Radian(1).ToDegrees().Float64()
	fmt.Printf("Degrees: %.4f degrees\n", val)

	val = Degree(val).ToRadians().Float64()
	fmt.Printf("Rad: %.4f radians\n", val)
}

// Function to convert degrees to radians
func degreesToRadians(deg float64) float64 {
	return deg * (math.Pi / 180.0)
}

// Function to convert radians to degrees
func radiansToDegrees(rad float64) float64 {
	return rad * (180.0 / math.Pi)
}



// This program demonstrates logarithmic functions in Go:
// Ln (natural logarithm), Log10 (base-10 logarithm), Log2 (base-2 logarithm),
// and a custom logarithm function (Log) with a specified base.
package main

import (
	"fmt"
	"math"
)

func main() {

	ln := math.Log(math.E)
	fmt.Printf("Ln(E) = %.4f\n", ln)

	log10 := math.Log10(-100)
	fmt.Printf("Log10(10) = %.4f\n", log10)

	log2 := math.Log2(2)
	fmt.Printf("Log2(2) = %.4f\n", log2)

	log_3_6 := Log(3, 6)
	fmt.Printf("Log3(6) = %.4f\n", log_3_6)

}

// Log computes the logarithm of base > 1 and x greater 0
func Log(base, x float64) float64 {
	return math.Log(x) / math.Log(base)
}



// This program calculates MD5 checksums for a string and a file.

package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

var content = "This is content to check"

func main() {

	checksum := MD5(content)
	checksum2 := FileMD5("content.dat")

	fmt.Printf("Checksum 1: %s\n", checksum)
	fmt.Printf("Checksum 2: %s\n", checksum2)
	if checksum == checksum2 {
		fmt.Println("Content matches!!!")
	}

}

// MD5 calculates the MD5 hash of the given data and returns it as a hex-encoded string.
func MD5(data string) string {
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}

// FileMD5 calculates the MD5 hash of a file's content and returns it as a hex-encoded string.
func FileMD5(path string) string {
	h := md5.New()
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}



// This program demonstrates how to create a new SHA-1 hash instance using the crypto package in Go.

package main

import (
	"crypto"
)

func main() {
	crypto.SHA1.New()
}



// This program demonstrates how to retrieve and print the current date and time using the time package in Go.

package main

import (
	"fmt"
	"time"
)

func main() {

	today := time.Now()
	fmt.Println(today)

}



// This program demonstrates various ways to format a specific time value using the time package in Go.

package main

import (
	"fmt"
	"time"
)

func main() {
	tTime := time.Date(2017, time.March, 5, 8, 5, 2, 0, time.Local)

	// Formatting with a custom layout
	fmt.Printf("tTime is: %s\n", tTime.Format("2006/1/2"))

	// Formatting hours and minutes
	fmt.Printf("The time is: %s\n", tTime.Format("15:04"))

	// Using predefined RFC1123 format
	fmt.Printf("The time is: %s\n", tTime.Format(time.RFC1123))

	// Space padding for days (Go 1.9.2+)
	fmt.Printf("tTime is: %s\n", tTime.Format("2006/1/_2"))

	// Zero-padding for days, months, and hours
	fmt.Printf("tTime is: %s\n", tTime.Format("2006/01/02"))

	// Fractional seconds with leading zeros
	fmt.Printf("tTime is: %s\n", tTime.Format("15:04:05.00"))

	// Fractional seconds without leading zeros
	fmt.Printf("tTime is: %s\n", tTime.Format("15:04:05.999"))

	// AppendFormat example
	fmt.Println(string(tTime.AppendFormat([]byte("The time is up: "), "03:04PM")))
}



// This program demonstrates parsing of date and time strings using the time package in Go,
// handling different time zone scenarios with Parse and ParseInLocation functions.

package main

import (
	"fmt"
	"time"
)

func main() {

	// If timezone is not defined, Parse function returns the time in UTC timezone.
	t, err := time.Parse("2/1/2006", "31/7/2015")
	if err != nil {
		panic(err)
	}
	fmt.Println(t)

	// If timezone is given, it is parsed in the specified timezone.
	t, err = time.Parse("2/1/2006  3:04 PM MST", "31/7/2015  1:25 AM DST")
	if err != nil {
		panic(err)
	}
	fmt.Println(t)

	// ParseInLocation parses the time in the given location if the string does not contain time zone definition.
	t, err = time.ParseInLocation("2/1/2006  3:04 PM ", "31/7/2015  1:25 AM ", time.Local)
	if err != nil {
		panic(err)
	}
	fmt.Println(t)

}



// This program demonstrates how to work with epoch time (Unix time) using the time package in Go.

package main

import (
	"fmt"
	"time"
)

func main() {

	// Set the epoch time from int64
	t := time.Unix(0, 0)
	fmt.Println(t)

	// Get the epoch time from a Time instance
	epoch := t.Unix()
	fmt.Println(epoch)

	// Current epoch time in seconds
	epochNow := time.Now().Unix()
	fmt.Printf("Epoch time in seconds: %d\n", epochNow)

	// Current epoch time in nanoseconds
	epochNano := time.Now().UnixNano()
	fmt.Printf("Epoch time in nano-seconds: %d\n", epochNano)

}



// This program demonstrates extracting date and time units from a specific time instance using the time package in Go.

package main

import (
	"fmt"
	"time"
)

func main() {
	t := time.Date(2017, 11, 29, 21, 0, 0, 0, time.Local)
	fmt.Printf("Extracting units from: %v\n", t)

	dOfMonth := t.Day()
	weekDay := t.Weekday()
	month := t.Month()

	fmt.Printf("The %dth day of %v is %v\n", dOfMonth, month, weekDay)
}



// This program demonstrates manipulating dates and times using the time package in Go,
// including adding and subtracting durations and using a more convenient API for adding years, months, and days.

package main

import (
	"fmt"
	"time"
)

func main() {

	l, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		panic(err)
	}
	t := time.Date(2017, 11, 30, 11, 10, 20, 0, l)
	fmt.Printf("Default date is: %v\n", t)

	// Add 3 days
	r1 := t.Add(72 * time.Hour)
	fmt.Printf("Default date +3 days is: %v\n", r1)

	// Subtract 3 days
	r1 = t.Add(-72 * time.Hour)
	fmt.Printf("Default date -3 days is: %v\n", r1)

	// Using AddDate to add years, months, and days
	r1 = t.AddDate(1, 3, 2)
	fmt.Printf("Default date +1 year +3 months +2 days is: %v\n", r1)
}



// This program demonstrates calculating durations between dates using the time package in Go,
// including calculating durations between specific dates, from a date to the present, and from the present to a date.

package main

import (
	"fmt"
	"time"
)

func main() {

	l, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		panic(err)
	}

	t := time.Date(2000, 1, 1, 0, 0, 0, 0, l)
	t2 := time.Date(2000, 1, 3, 0, 0, 0, 0, l)
	fmt.Printf("First Default date is %v\n", t)
	fmt.Printf("Second Default date is %v\n", t2)

	dur := t2.Sub(t)
	fmt.Printf("The duration between t and t2 is %v\n", dur)

	dur = time.Since(t)
	fmt.Printf("The duration between now and t is %v\n", dur)

	dur = time.Until(t)
	fmt.Printf("The duration between t and now is %v\n", dur)

}



// This program demonstrates how to convert a time from one timezone (Europe/Vienna) to another (America/Phoenix) using Go's time package and the In() method.

package main

import (
	"fmt"
	"time"
)

func main() {
	eur, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		panic(err)
	}

	t := time.Date(2000, 1, 1, 0, 0, 0, 0, eur)
	fmt.Printf("Original Time: %v\n", t)

	phx, err := time.LoadLocation("America/Phoenix")
	if err != nil {
		panic(err)
	}

	t2 := t.In(phx)
	fmt.Printf("Converted Time: %v\n", t2)
}



// This program demonstrates how to handle OS signals to gracefully stop a goroutine that uses a ticker.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
)

func main() {

	c := make(chan os.Signal, 1)
	signal.Notify(c)

	ticker := time.NewTicker(time.Second)
	stop := make(chan bool)

	go func() {
		defer func() { stop <- true }()
		for {
			select {
			case <-ticker.C:
				fmt.Println("Tick")
			case <-stop:
				fmt.Println("Goroutine closing")
				return
			}
		}
	}()

	// Block until the signal is received
	<-c
	ticker.Stop()

	// Stop the goroutine
	stop <- true
	// Wait until the goroutine stops
	<-stop
	fmt.Println("Application stopped")
}



// This program demonstrates different ways to wait for a duration using time.Timer, time.AfterFunc, and time.After.

package main

import (
	"fmt"
	"sync"
	"time"
)

func main() {

	t := time.NewTimer(3 * time.Second)
	fmt.Printf("Start waiting at %v\n", time.Now().Format(time.UnixDate))
	<-t.C
	fmt.Printf("Code executed at %v\n", time.Now().Format(time.UnixDate))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	fmt.Printf("Start waiting for AfterFunc at %v\n", time.Now().Format(time.UnixDate))
	time.AfterFunc(3*time.Second, func() {
		fmt.Printf("Code executed for AfterFunc at %v\n", time.Now().Format(time.UnixDate))
		wg.Done()
	})

	wg.Wait()

	fmt.Printf("Waiting on time.After at %v\n", time.Now().Format(time.UnixDate))
	<-time.After(3 * time.Second)
	fmt.Printf("Code resumed at %v\n", time.Now().Format(time.UnixDate))

}



// This program demonstrates how to insert items into a list until a timeout using time.After.

package main

import (
	"fmt"
	"time"
)

func main() {

	to := time.After(3 * time.Second)
	list := make([]string, 0)
	done := make(chan bool, 1)

	fmt.Println("Starting to insert items")
	go func() {
		defer fmt.Println("Exiting goroutine")
		for {
			select {
			case <-to:
				fmt.Println("The time is up")
				done <- true
				return
			default:
				list = append(list, time.Now().String())
			}
		}
	}()

	<-done
	fmt.Printf("Managed to insert %d items\n", len(list))

}



// This program demonstrates how to serialize and deserialize time.Time values using JSON encoding.

package main

import (
	"encoding/json"
	"fmt"
	"time"
)

func main() {

	// Load the Europe/Vienna time zone location
	eur, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		panic(err)
	}

	// Create a time instance in the Europe/Vienna time zone
	t := time.Date(2017, 11, 20, 11, 20, 10, 0, eur)

	// Serialize as RFC 3339
	b, err := t.MarshalJSON()
	if err != nil {
		panic(err)
	}
	fmt.Println("Serialized as RFC 3339:", string(b))

	// Deserialize from RFC 3339
	t2 := time.Time{}
	t2.UnmarshalJSON(b)
	fmt.Println("Deserialized from RFC 3339:", t2)

	// Serialize as epoch
	epoch := t.Unix()
	fmt.Println("Serialized as Epoch:", epoch)

	// Deserialize from epoch
	jsonStr := fmt.Sprintf("{ \"created\":%d }", epoch)
	data := struct {
		Created int64 `json:"created"`
	}{}
	json.Unmarshal([]byte(jsonStr), &data)
	deserialized := time.Unix(data.Created, 0)
	fmt.Println("Deserialized from Epoch:", deserialized)
}










// The code  prompts for and reads the user's name and age, then prints a greeting with that information.
package main

import (
	"fmt"
)

func main() {

	var name string
	fmt.Println("What is your name?")
	fmt.Scanf("%s\n", &name)

	var age int
	fmt.Println("What is your age?")
	fmt.Scanf("%d\n", &age)

	fmt.Printf("Hello %s, your age is %d\n", name, age)

}

// The code reads input from the user in 8-byte chunks, then prints the hexadecimal and string representation of each chunk.
package main

import (
	"fmt"
	"os"
)

func main() {

	for {
		data := make([]byte, 8)
		n, err := os.Stdin.Read(data)
		if err == nil && n > 0 {
			process(data)
		} else {
			break
		}
	}

}

func process(data []byte) {
	fmt.Printf("Received: %X 	%s\n", data, string(data))
}

// This code reads lines of input from the user and echoes each line back to the console prefixed with "Echo:".
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {

	// The Scanner is able to
	// scan input by lines
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		txt := sc.Text()
		fmt.Printf("Echo: %s\n", txt)
	}

}

// This code writes strings to standard output and error, then writes a byte buffer to standard output repeatedly, followed by a newline.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {

	// Simply write string
	io.WriteString(os.Stdout,
		"This is string to standard output.\n")

	io.WriteString(os.Stderr,
		"This is string to standard error output.\n")

	// Stdout/err implements
	// writer interface
	buf := []byte{0xAF, 0xFF, 0xFE}
	for i := 0; i < 200; i++ {
		if _, e := os.Stdout.Write(buf); e != nil {
			panic(e)
		}
	}

	// The fmt package
	// could be used too
	fmt.Fprintln(os.Stdout, "\n")
}

// This code reads and prints a file's content, then creates or opens another file to write "Test string" into it.
//file.txt content: This is file content.
//test.txt content: Test string

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {

	f, err := os.Open("temp/file.txt")
	if err != nil {
		panic(err)
	}

	c, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Printf("### File content ###\n%s\n", string(c))
	f.Close()

	f, err = os.OpenFile("temp/test.txt", os.O_CREATE|os.O_RDWR, 0777)
	if err != nil {
		panic(err)
	}
	io.WriteString(f, "Test string")
	f.Close()

}


// Read "temp/file.txt" using bufio.Scanner line by line into bytes.Buffer,
// and print accumulated content. Then read entire file using ioutil.ReadFile,
// convert to string, and print directly, achieving the same file reading goal.
/*file content: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris id pretium eros. Aliquam imperdiet mi ut elit faucibus porta.
Donec facilisis nunc at risus dapibus elementum.
*/
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	fmt.Println("### Read as reader ###")
	f, err := os.Open("temp/file.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Read the
	// file with reader
	wr := bytes.Buffer{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		wr.WriteString(sc.Text())
	}
	fmt.Println(wr.String())

	fmt.Println("### ReadFile ###")
	// for smaller files
	fContent, err := ioutil.ReadFile("temp/file.txt")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(fContent))

}

// This code encodes a string in Windows-1252 encoding, writes it to "example.txt", then reads and decodes it back to UTF-8, printing the decoded content.
//example.txt content: This is sample text with runes Š

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/text/encoding/charmap"
)

func main() {

	// Write the string
	// encoded to Windows-1252
	encoder := charmap.Windows1252.NewEncoder()
	s, e := encoder.String("This is sample text with runes Š")
	if e != nil {
		panic(e)
	}
	ioutil.WriteFile("example.txt", []byte(s), os.ModePerm)

	// Decode to UTF-8
	f, e := os.Open("example.txt")
	if e != nil {
		panic(e)
	}
	defer f.Close()
	decoder := charmap.Windows1252.NewDecoder()
	reader := decoder.Reader(f)
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}



//This Go program manipulates a fixed-format flat file (flatfile.txt) with each line //of 25 characters.
//It reads specific lines, writes data into columns ("id", "first", "last"), and //manages file operations and data errors.
//It showcases structured data manipulation in a flat file, emphasizing basic file //handling and error management.
/*
content of flatfile.txt: 123.Jun.......Wong......
12..Novak.....Jurgen....
10..Radomir...Sohlich...                                                                                                                                                                                    Andrew....
*/
package main

import (
	"errors"
	"fmt"
	"os"
)

const lineLegth = 25

func main() {

	f, e := os.OpenFile("flatfile.txt", os.O_RDWR|os.O_CREATE, os.ModePerm)
	if e != nil {
		panic(e)
	}
	defer f.Close()

	fmt.Println(readRecords(2, "last", f))
	if err := writeRecord(2, "first", "Radomir", f); err != nil {
		panic(err)
	}
	fmt.Println(readRecords(2, "first", f))
	if err := writeRecord(10, "first", "Andrew", f); err != nil {
		panic(err)
	}
	fmt.Println(readRecords(10, "first", f))
	fmt.Println(readLine(2, f))
}

func readLine(line int, f *os.File) (string, error) {
	lineBuffer := make([]byte, 24)
	f.Seek(int64(line*lineLegth), 0)
	_, err := f.Read(lineBuffer)
	return string(lineBuffer), err
}

func writeRecord(line int, column, dataStr string, f *os.File) error {
	definedLen := 10
	position := int64(line * lineLegth)
	switch column {
	case "id":
		definedLen = 4
	case "first":
		position += 4
	case "last":
		position += 14
	default:
		return errors.New("Column not defined")
	}

	if len([]byte(dataStr)) > definedLen {
		return fmt.Errorf("Maximum length for '%s' is %d", column, definedLen)
	}

	data := make([]byte, definedLen)
	for i := range data {
		data[i] = '.'
	}
	copy(data, []byte(dataStr))
	_, err := f.WriteAt(data, position)
	return err
}

func readRecords(line int, column string, f *os.File) (string, error) {
	lineBuffer := make([]byte, 24)
	f.ReadAt(lineBuffer, int64(line*lineLegth))
	var retVal string
	switch column {
	case "id":
		return string(lineBuffer[:3]), nil
	case "first":
		return string(lineBuffer[4:13]), nil
	case "last":
		return string(lineBuffer[14:23]), nil
	}

	return retVal, errors.New("Column not defined")
}

// Writing binary values: writes a float64 (1.004) and a string ("Hello") to a buffer using binary encoding.
// Reading the written values: reads a float64 and a string from the buffer and prints them formatted.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func main() {

	// Writing binary values
	buf := bytes.NewBuffer([]byte{})
	if err := binary.Write(buf, binary.BigEndian, 1.004); err != nil {
		panic(err)
	}
	if err := binary.Write(buf, binary.BigEndian, []byte("Hello")); err != nil {
		panic(err)
	}

	// Reading the written values
	var num float64
	if err := binary.Read(buf, binary.BigEndian, &num); err != nil {
		panic(err)
	}
	fmt.Printf("float64: %.3f\n", num)
	greeting := make([]byte, 5)
	if err := binary.Read(buf, binary.BigEndian, &greeting); err != nil {
		panic(err)
	}
	fmt.Printf("string: %s\n", string(greeting))
}

// Creates a buffer and a file "sample.txt", writes a string into both using MultiWriter,
// then prints the contents of the buffer.
//sample.txt content: Hello, Go is awesome!
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func main() {

	buf := bytes.NewBuffer([]byte{})
	f, err := os.OpenFile("sample.txt", os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		panic(err)
	}
	wr := io.MultiWriter(buf, f)
	_, err = io.WriteString(wr, "Hello, Go is awesome!")
	if err != nil {
		panic(err)
	}

	fmt.Println("Content of buffer: " + buf.String())
}

// Uses a pipe to capture output from executing "echo Hello Go!\nThis is example",
// then prints the output to the console using io.Copy and goroutines.
package main

import (
	"io"
	"log"
	"os"
	"os/exec"
)

func main() {
	pReader, pWriter := io.Pipe()

	cmd := exec.Command("echo", "Hello Go!\nThis is example")
	cmd.Stdout = pWriter

	go func() {
		defer pReader.Close()
		if _, err := io.Copy(os.Stdout, pReader); err != nil {
			log.Fatal(err)
		}
	}()

	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}

}

// Encodes a User struct into a byte buffer using gob encoding,
// then decodes it back into a User struct and prints its string representation.
// Also tries to decode into a SimpleUser struct but fails due to data format mismatch.
package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type User struct {
	FirstName string
	LastName  string
	Age       int
	Active    bool
}

func (u User) String() string {
	return fmt.Sprintf(`{"FirstName":%s,"LastName":%s,"Age":%d,"Active":%v }`,
		u.FirstName, u.LastName, u.Age, u.Active)
}

type SimpleUser struct {
	FirstName string
	LastName  string
}

func (u SimpleUser) String() string {
	return fmt.Sprintf(`{"FirstName":%s,"LastName":%s}`,
		u.FirstName, u.LastName)
}

func main() {

	var buff bytes.Buffer

	// Encode value
	enc := gob.NewEncoder(&buff)
	user := User{
		"Radomir",
		"Sohlich",
		30,
		true,
	}
	enc.Encode(user)
	fmt.Printf("%X\n", buff.Bytes())

	// Decode value
	out := User{}
	dec := gob.NewDecoder(&buff)
	dec.Decode(&out)
	fmt.Println(out.String())

	enc.Encode(user)
	out2 := SimpleUser{}
	dec.Decode(&out2)
	fmt.Println(out2.String())

}

// Compresses "This is my file content" into a ZIP file "data.zip" and writes it to disk.
// Then decompresses "data.zip", reads "newfile.txt", and prints its content to stdout.
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	var buff bytes.Buffer

	// Compress content
	zipW := zip.NewWriter(&buff)
	f, err := zipW.Create("newfile.txt")
	if err != nil {
		panic(err)
	}
	_, err = f.Write([]byte("This is my file content"))
	if err != nil {
		panic(err)
	}
	err = zipW.Close()
	if err != nil {
		panic(err)
	}

	//Write output to file
	err = ioutil.WriteFile("data.zip", buff.Bytes(), os.ModePerm)
	if err != nil {
		panic(err)
	}

	// Decompress the content
	zipR, err := zip.OpenReader("data.zip")
	if err != nil {
		panic(err)
	}

	for _, file := range zipR.File {
		fmt.Println("File " + file.Name + " contains:")
		r, err := file.Open()
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(os.Stdout, r)
		if err != nil {
			panic(err)
		}
		err = r.Close()
		if err != nil {
			panic(err)
		}
		fmt.Println()
	}

}

// Reads and parses XML data from "data.xml" into a slice of Book structs,
// using xml.Decoder to decode each <book> element into a Book struct and prints them.
package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

type Book struct {
	Title  string `xml:"title"`
	Author string `xml:"author"`
}

func main() {

	f, err := os.Open("data.xml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	decoder := xml.NewDecoder(f)

	// Read the book one by one
	books := make([]Book, 0)
	for {
		tok, err := decoder.Token()
		if err != nil {
			panic(err)
		}
		if tok == nil {
			break
		}
		switch tp := tok.(type) {
		case xml.StartElement:
			if tp.Name.Local == "book" {
				// Decode the element to struct
				var b Book
				decoder.DecodeElement(&b, &tp)
				books = append(books, b)
			}
		}
	}
	fmt.Println(books)
}

// Parses JSON data from a constant string js representing an array of User objects,
// using json.NewDecoder to decode each object into a User struct and prints the slice of users.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

const js = `
	[{
		"name":"Axel",
		"lastname":"Fooley"
	},
	{
		"name":"Tim",
		"lastname":"Burton"
	},
	{
		"name":"Tim",
		"lastname":"Burton"
`

type User struct {
	Name     string `json:"name"`
	LastName string `json:"lastname"`
}

func main() {

	userSlice := make([]User, 0)
	r := strings.NewReader(js)
	dec := json.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if tok == nil {
			break
		}
		switch tp := tok.(type) {
		case json.Delim:
			str := tp.String()
			if str == "[" || str == "{" {
				for dec.More() {
					u := User{}
					err := dec.Decode(&u)
					if err == nil {
						userSlice = append(userSlice, u)
					} else {
						break
					}
				}
			}
		}
	}

	fmt.Println(userSlice)
}

// Opens and retrieves information about "test.file":
// prints its name, whether it's a directory, its size, and mode.
package main

import (
	"fmt"
	"os"
)

func main() {

	f, err := os.Open("test.file")
	if err != nil {
		panic(err)
	}
	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}

	fmt.Printf("File name: %v\n", fi.Name())
	fmt.Printf("Is Directory: %t\n", fi.IsDir())
	fmt.Printf("Size: %d\n", fi.Size())
	fmt.Printf("Mode: %v\n", fi.Mode())

}

// Creates a temporary file and directory using ioutil.TempFile and ioutil.TempDir respectively,
// printing their names. Deferred cleanup ensures removal after program execution.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	tFile, err := ioutil.TempFile("", "gostdcookbook")
	if err != nil {
		panic(err)
	}
	// The called is responsible for handling
	// the clean up.
	defer os.Remove(tFile.Name())

	fmt.Println(tFile.Name())

	// TempDir returns
	// the path in string.
	tDir, err := ioutil.TempDir("", "gostdcookbookdir")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tDir)
	fmt.Println(tDir)

}

// Creates a file "sample.file", writes "Go is awesome!" and "Yeah! Go is great." to it using os.Create and io.Copy,
// demonstrating file writing and copying in Go, with deferred file closure for cleanup.
package main

import (
	"io"
	"os"
	"strings"
)

func main() {

	f, err := os.Create("sample.file")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.WriteString("Go is awesome!\n")
	if err != nil {
		panic(err)
	}

	_, err = io.Copy(f, strings.NewReader("Yeah! Go is great.\n"))
	if err != nil {
		panic(err)
	}
}

// Creates "sample.file" and writes concurrent greetings ("Hello!", "Ola!", "Ahoj!") using SyncWriter,
// ensuring thread safety with sync.Mutex and sync.WaitGroup.
package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type SyncWriter struct {
	m      sync.Mutex
	Writer io.Writer
}

func (w *SyncWriter) Write(b []byte) (n int, err error) {
	w.m.Lock()
	defer w.m.Unlock()
	return w.Writer.Write(b)
}

var data = []string{
	"Hello!",
	"Ola!",
	"Ahoj!",
}

func main() {

	f, err := os.Create("sample.file")
	if err != nil {
		panic(err)
	}

	wr := &SyncWriter{sync.Mutex{}, f}
	wg := sync.WaitGroup{}
	for _, val := range data {
		wg.Add(1)
		go func(greetings string) {
			fmt.Fprintln(wr, greetings)
			wg.Done()
		}(val)
	}

	wg.Wait()
}

// Lists files and directories in the current directory using ioutil.ReadDir and filepath.Walk respectively.
// Walk lists recursively and skips directories, printing them in brackets.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func main() {

	fmt.Println("List by ReadDir")
	listDirByReadDir(".")
	fmt.Println()
	fmt.Println("List by Walk")
	listDirByWalk(".")
}

func listDirByWalk(path string) {
	filepath.Walk(path, func(wPath string, info os.FileInfo, err error) error {

		// Walk the given dir
		// without printing out.
		if wPath == path {
			return nil
		}

		// If given path is folder
		// stop list recursively and print as folder.
		if info.IsDir() {
			fmt.Printf("[%s]\n", wPath)
			return filepath.SkipDir
		}

		// Print file name
		if wPath != path {
			fmt.Println(wPath)
		}
		return nil
	})
}

func listDirByReadDir(path string) {
	lst, err := ioutil.ReadDir(path)
	if err != nil {
		panic(err)
	}
	for _, val := range lst {
		if val.IsDir() {
			fmt.Printf("[%s]\n", val.Name())
		} else {
			fmt.Println(val.Name())
		}
	}
}

// Creates "test.file", retrieves its initial permissions using os.Create and f.Stat.
// Changes permissions to 0777 using f.Chmod and verifies the change with f.Stat, printing both sets of permissions.
package main

import (
	"fmt"
	"os"
)

func main() {

	f, err := os.Create("test.file")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Obtain current permissions
	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}
	fmt.Printf("File permissions %v\n", fi.Mode())

	// Change permissions
	err = f.Chmod(0777)
	if err != nil {
		panic(err)
	}
	fi, err = f.Stat()
	if err != nil {
		panic(err)
	}
	fmt.Printf("File permissions %v\n", fi.Mode())

}

// Creates "created.file" using os.Create.
// Creates "created.byopen" with append mode using os.OpenFile.
// Creates directory "createdDir" using os.Mkdir.
// Creates nested directories "sampleDir/path1/path2" using os.MkdirAll.

package main

import (
	"os"
)

func main() {

	f, err := os.Create("created.file")
	if err != nil {
		panic(err)
	}
	f.Close()

	f, err = os.OpenFile("created.byopen", os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		panic(err)
	}
	f.Close()

	err = os.Mkdir("createdDir", 0777)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll("sampleDir/path1/path2", 0777)
	if err != nil {
		panic(err)
	}

}

// Creates six files named "test.file1" to "test.file6" using os.Create.
// Glob retrieves files matching pattern "test.file[1-3]" using filepath.Glob.
// Removes all created files after execution as cleanup using os.Remove.

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {

	for i := 1; i <= 6; i++ {
		_, err := os.Create(fmt.Sprintf("./test.file%d", i))
		if err != nil {
			fmt.Println(err)
		}
	}

	m, err := filepath.Glob("test.file[1-3]")
	if err != nil {
		panic(err)
	}

	for _, val := range m {
		fmt.Println(val)
	}

	// Cleanup
	for i := 1; i <= 6; i++ {
		err := os.Remove(fmt.Sprintf("./test.file%d", i))
		if err != nil {
			fmt.Println(err)
		}
	}
}

// Creates three files with content and permissions defined in `data`.
// Compares files by checksum using MD5 and line by line using bufio.Scanner.
// Cleans up created files after comparisons using os.Remove.

package main

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

var data = []struct {
	name string
	cont string
	perm os.FileMode
}{
	{"test1.file", "Hello\nGolang is great", 0666},
	{"test2.file", "Hello\nGolang is great", 0666},
	{"test3.file", "Not matching\nGolang is great\nLast line", 0666},
}

func main() {

	files := []*os.File{}
	for _, fData := range data {
		f, err := os.Create(fData.name)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = io.WriteString(f, fData.cont)
		if err != nil {
			panic(err)
		}
		files = append(files, f)
	}

	// Compare by checksum
	checksums := []string{}
	for _, f := range files {
		f.Seek(0, 0) // reset to beginngin of file
		sum, err := getMD5SumString(f)
		if err != nil {
			panic(err)
		}
		checksums = append(checksums, sum)
	}

	fmt.Println("### Comparing by checksum ###")
	compareCheckSum(checksums[0], checksums[1])
	compareCheckSum(checksums[0], checksums[2])

	fmt.Println("### Comparing line by line ###")
	files[0].Seek(0, 0)
	files[2].Seek(0, 0)
	compareFileByLine(files[0], files[2])

	// Cleanup
	for _, val := range data {
		os.Remove(val.name)
	}

}

func getMD5SumString(f *os.File) (string, error) {
	file1Sum := md5.New()
	_, err := io.Copy(file1Sum, f)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%X", file1Sum.Sum(nil)), nil
}

func compareCheckSum(sum1, sum2 string) {
	match := "match"
	if sum1 != sum2 {
		match = " does not match"
	}
	fmt.Printf("Sum: %s and Sum: %s %s\n", sum1, sum2, match)
}

func compareLines(line1, line2 string) {
	sign := "o"
	if line1 != line2 {
		sign = "x"
	}
	fmt.Printf("%s | %s | %s \n", sign, line1, line2)
}

func compareFileByLine(f1, f2 *os.File) {
	sc1 := bufio.NewScanner(f1)
	sc2 := bufio.NewScanner(f2)
	for {
		sc1Bool := sc1.Scan()
		sc2Bool := sc2.Scan()
		if !sc1Bool && !sc2Bool {
			break
		}
		compareLines(sc1.Text(), sc2.Text())
	}
}

// Retrieves the current user's information using user.Current() and prints the home directory.

package main

import (
	"fmt"
	"log"
	"os/user"
)

func main() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("The user home directory: " + usr.HomeDir)
}
























/*
Package main lists all network interfaces on the system and their associated IP addresses.

This program uses the `net` package to retrieve and display all network interfaces available
on the system along with their IP addresses. It handles any errors encountered during the
retrieval of interfaces or addresses by using `panic` to terminate the program with an error message.
*/
package main

import (
	"fmt"
	"net"
)

func main() {
	// Get all network interfaces on the system.
	// If there is an error in retrieving the interfaces, the program will terminate with a panic.
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Iterate through each network interface.
	for _, interf := range interfaces {
		// Resolve and display addresses for each interface.
		// If there is an error in retrieving the addresses, the program will terminate with a panic.
		addrs, err := interf.Addrs()
		if err != nil {
			panic(err)
		}

		// Print the name of the network interface.
		fmt.Println(interf.Name)

		// Iterate through each address associated with the interface.
		for _, add := range addrs {
			// Check if the address is of type *net.IPNet and print it.
			if ip, ok := add.(*net.IPNet); ok {
				fmt.Printf("\t%v\n", ip)
			}
		}
	}
}










/*
Package main demonstrates a simple HTTP server and client interaction in Go.

This package defines an HTTP server that responds with a static message and a client that connects to the server via plain TCP,
sends an HTTP GET request, and reads the response. The server is created using the `http` package, and the client uses the `net` package for TCP connection.
The server is gracefully shut down after handling the client request.
*/
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// StringServer represents a simple HTTP handler that serves a static string message.
type StringServer string

// ServeHTTP responds to HTTP requests with the static string message defined in StringServer.
func (s StringServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(string(s)))
}

// createServer initializes and returns an HTTP server listening on the specified address.
// The server uses StringServer as its handler to serve a static message.
func createServer(addr string) http.Server {
	return http.Server{
		Addr:    addr,
		Handler: StringServer("HELLO GOPHER!\n"),
	}
}

const addr = "localhost:7070"

func main() {
	// Create and start the HTTP server in a separate goroutine.
	s := createServer(addr)
	go s.ListenAndServe()

	// Establish a plain TCP connection to the server.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Send an HTTP GET request to the server.
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost:7070\r\n\r\n")
	if err != nil {
		panic(err)
	}

	// Read and print the server's response.
	scanner := bufio.NewScanner(conn)
	conn.SetReadDeadline(time.Now().Add(time.Second)) // Set a read deadline for the TCP connection.
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	// Gracefully shut down the HTTP server with a 5-second timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}










/*
Package main demonstrates DNS lookup functionalities for resolving IP addresses and hostnames.

This program resolves the hostnames associated with the loopback IP address (`127.0.0.1`) and the IP addresses for the hostname `localhost`.
It uses functions from the `net` package to perform these lookups and prints the results to the console.
*/
package main

import (
	"fmt"
	"net"
)

func main() {
	// Resolve the hostname associated with the loopback IP address (127.0.0.1).
	// If there is an error during the lookup, the program will terminate with a panic.
	addrs, err := net.LookupAddr("127.0.0.1")
	if err != nil {
		panic(err)
	}

	// Print each resolved hostname.
	for _, addr := range addrs {
		fmt.Println(addr)
	}

	// Resolve the IP addresses associated with the hostname "localhost".
	// If there is an error during the lookup, the program will terminate with a panic.
	ips, err := net.LookupIP("localhost")
	if err != nil {
		panic(err)
	}

	// Print each resolved IP address.
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
}










/*
Package main demonstrates how to create a simple HTTP server in Go and interact with it using POST requests.

This package defines an HTTP server that responds with a static message and logs received form data. It also provides
two examples of sending POST requests to the server using the `http` package: one with `http.Post` and one with `http.NewRequest`.
The responses from the server are printed to the console.
*/
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// StringServer represents a simple HTTP handler that serves a static string message.
type StringServer string

// ServeHTTP responds to HTTP requests with the static string message defined in StringServer.
// It also parses and prints any form data received in the request.
func (s StringServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	fmt.Printf("Received form data: %v\n", req.Form)
	rw.Write([]byte(string(s)))
}

// createServer initializes and returns an HTTP server listening on the specified address.
// The server uses StringServer as its handler to serve a static message.
func createServer(addr string) http.Server {
	return http.Server{
		Addr:    addr,
		Handler: StringServer("Hello world"),
	}
}

const addr = "localhost:7070"

func main() {
	// Create and start the HTTP server in a separate goroutine.
	s := createServer(addr)
	go s.ListenAndServe()

	// Send a POST request to the server using http.Post.
	simplePost()

	// Send a POST request to the server using a custom http.Request.
	useRequest()
}

// simplePost sends a POST request with form data to the HTTP server using http.Post.
// It prints the response from the server to the console.
func simplePost() {
	res, err := http.Post("http://localhost:7070",
		"application/x-www-form-urlencoded",
		strings.NewReader("name=Radek&surname=Sohlich"))
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("Response from server:" + string(data))
}

// useRequest sends a POST request with form data to the HTTP server using a custom http.Request.
// It prints the response from the server to the console.
func useRequest() {
	hc := http.Client{}
	form := url.Values{}
	form.Add("name", "Radek")
	form.Add("surname", "Sohlich")

	req, err := http.NewRequest("POST",
		"http://localhost:7070",
		strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := hc.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("Response from server:" + string(data))
}










/*
Package main demonstrates the creation, parsing, and serialization of URLs in Go.

This program constructs a URL using the `url.URL` struct, prints it, and then parses the constructed URL back
into a URL object. It also serializes the parsed URL object into a JSON format for display.
*/
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func main() {
	// Create and assemble a URL using the url.URL struct.
	u := &url.URL{}
	u.Scheme = "http"                     // Set the URL scheme (e.g., "http").
	u.Host = "localhost"                  // Set the host (e.g., "localhost").
	u.Path = "index.html"                 // Set the path (e.g., "index.html").
	u.RawQuery = "id=1&name=John"         // Set the raw query parameters (e.g., "id=1&name=John").
	u.User = url.UserPassword("admin", "1234") // Set the user credentials (e.g., username and password).

	// Print the assembled URL.
	fmt.Printf("Assembled URL:\n%v\n\n\n", u)

	// Parse the assembled URL string back into a URL object.
	parsedURL, err := url.Parse(u.String())
	if err != nil {
		panic(err)
	}

	// Serialize the parsed URL object to JSON.
	jsonURL, err := json.Marshal(parsedURL)
	if err != nil {
		panic(err)
	}

	// Print the serialized JSON representation of the parsed URL.
	fmt.Println("Parsed URL:")
	fmt.Println(string(jsonURL))
}










/*
Package main demonstrates creating an HTTP server in Go and sending a POST request with form data and headers.

This program sets up a simple HTTP server that handles incoming requests, prints received form data and headers,
and responds with a static message. It also creates a POST request to this server with specific form data and headers,
and then prints the server's response.
*/
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// StringServer represents a simple HTTP handler that serves a static string message.
type StringServer string

// ServeHTTP responds to HTTP requests with the static string message defined in StringServer.
// It also parses and prints any form data and headers received in the request.
func (s StringServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	fmt.Printf("Received form data: %v\n", req.Form)
	fmt.Printf("Received header: %v\n", req.Header)
	rw.Write([]byte(string(s)))
}

// createServer initializes and returns an HTTP server listening on the specified address.
// The server uses StringServer as its handler to serve a static message.
func createServer(addr string) http.Server {
	return http.Server{
		Addr:    addr,
		Handler: StringServer("Hello world"),
	}
}

const addr = "localhost:7070"

func main() {
	// Create and start the HTTP server in a separate goroutine.
	s := createServer(addr)
	go s.ListenAndServe()

	// Prepare form data for the POST request.
	form := url.Values{}
	form.Set("id", "5")
	form.Set("name", "Wolfgang")

	// Create a new POST request with the form data and the appropriate content type.
	req, err := http.NewRequest(http.MethodPost,
		"http://localhost:7070",
		strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the POST request and handle the response.
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	// Read and print the response from the server.
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println("Response from server:" + string(data))
}










/*
Package main demonstrates basic operations on HTTP headers using the `http.Header` type in Go.

This program performs various operations on HTTP headers, including setting, adding, retrieving, replacing,
and deleting header values. It prints the header state after each operation to illustrate the changes.
*/
package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Create a new HTTP header.
	header := http.Header{}

	// Set the header "Auth-X" to a single value "abcdef1234".
	header.Set("Auth-X", "abcdef1234")

	// Add another value "defghijkl" to the header "Auth-X".
	header.Add("Auth-X", "defghijkl")

	// Print the current state of the header.
	fmt.Println(header)

	// Retrieve all values associated with the header "Auth-X".
	resSlice := header["Auth-X"]
	fmt.Println(resSlice)

	// Get the first value associated with the header "Auth-X".
	resFirst := header.Get("Auth-X")
	fmt.Println(resFirst)

	// Replace all existing values of the header "Auth-X" with a new value "newvalue".
	header.Set("Auth-X", "newvalue")
	fmt.Println(header)

	// Remove the header "Auth-X".
	header.Del("Auth-X")
	fmt.Println(header)
}










/*
Package main demonstrates how to handle HTTP redirects and track redirection counts in Go.

This program sets up an HTTP server that responds with temporary redirects (/redirect1, /redirect2, etc.) based on the number of redirections.
It also creates an HTTP client that handles redirects and limits the maximum number of redirects to 2. It prints details of each redirect
and stops if the maximum redirect count is exceeded.
*/
package main

import (
	"fmt"
	"net/http"
)

// addr represents the address and port on which the HTTP server listens.
const addr = "localhost:7070"

// RedirecServer is a struct that implements the http.Handler interface.
// It handles incoming HTTP requests and performs redirects based on a redirect count.
type RedirecServer struct {
	redirectCount int
}

// ServeHTTP handles incoming HTTP requests and performs a temporary redirect to the next redirect path.
// It increments the redirect count and sets a custom header "Known-redirects" with the current count.
func (s *RedirecServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s.redirectCount++
	fmt.Println("Received header: " + req.Header.Get("Known-redirects"))
	// Perform a temporary redirect to the next redirection path (/redirect1, /redirect2, etc.).
	http.Redirect(rw, req, fmt.Sprintf("/redirect%d", s.redirectCount), http.StatusTemporaryRedirect)
}

func main() {
	// Create an HTTP server with a RedirecServer handler.
	s := http.Server{
		Addr:    addr,
		Handler: &RedirecServer{0}, // Start with redirectCount set to 0.
	}
	go s.ListenAndServe() // Start the HTTP server in a separate goroutine.

	// Create an HTTP client.
	client := http.Client{}
	redirectCount := 0

	// Configure the client to handle redirects and limit the maximum number of redirects to 2.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		fmt.Println("Redirected")
		// Limit the maximum number of redirects to 2.
		if redirectCount > 2 {
			return fmt.Errorf("Too many redirects")
		}
		// Set a custom header "Known-redirects" with the current redirect count.
		req.Header.Set("Known-redirects", fmt.Sprintf("%d", redirectCount))
		redirectCount++
		// Print details of each previous request in the redirection chain.
		for _, prReq := range via {
			fmt.Printf("Previous request: %v\n", prReq.URL)
		}
		return nil
	}

	// Perform a GET request to the HTTP server.
	_, err := client.Get("http://" + addr)
	if err != nil {
		panic(err)
	}
}










/*
Package main demonstrates basic CRUD operations (Create, Read) using an HTTP server and client in Go.

This program sets up an HTTP server that manages a list of cities. It allows clients to retrieve the list of cities
via a GET request, and add a new city via a POST request. It also provides a client interface to fetch the list of cities
and save a new city to the server.
*/
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// addr represents the address and port on which the HTTP server listens.
const addr = "localhost:7070"

// City represents a city with its ID, name, and location.
type City struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
}

// toJson converts a City struct to its JSON string representation.
func (c City) toJson() string {
	return fmt.Sprintf(`{"name":"%s","location":"%s"}`, c.Name, c.Location)
}

func main() {
	// Create and start the HTTP server in a separate goroutine.
	s := createServer(addr)
	go s.ListenAndServe()

	// Retrieve the list of cities from the server.
	cities, err := getCities()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Retrieved cities: %v\n", cities)

	// Save a new city "Paris" to the server.
	city, err := saveCity(City{"", "Paris", "France"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Saved city: %v\n", city)
}

// saveCity sends a POST request to save a new city to the server.
// It returns the saved City object and any error encountered.
func saveCity(city City) (City, error) {
	r, err := http.Post("http://"+addr+"/cities", "application/json", strings.NewReader(city.toJson()))
	if err != nil {
		return City{}, err
	}
	defer r.Body.Close()
	return decodeCity(r.Body)
}

// getCities sends a GET request to retrieve the list of cities from the server.
// It returns a slice of City objects and any error encountered.
func getCities() ([]City, error) {
	r, err := http.Get("http://" + addr + "/cities")
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	return decodeCities(r.Body)
}

// decodeCity decodes a JSON-encoded City object from the provided reader.
// It returns the decoded City object and any error encountered during decoding.
func decodeCity(r io.Reader) (City, error) {
	city := City{}
	dec := json.NewDecoder(r)
	err := dec.Decode(&city)
	return city, err
}

// decodeCities decodes a JSON-encoded slice of City objects from the provided reader.
// It returns the decoded slice of City objects and any error encountered during decoding.
func decodeCities(r io.Reader) ([]City, error) {
	cities := []City{}
	dec := json.NewDecoder(r)
	err := dec.Decode(&cities)
	return cities, err
}

// createServer creates and returns an HTTP server configured to handle city-related requests.
// It initializes with a predefined set of cities and uses a multiplexer (mux) to route requests.
func createServer(addr string) http.Server {
	// Predefined list of cities.
	cities := []City{
		{ID: "1", Name: "Prague", Location: "Czechia"},
		{ID: "2", Name: "Bratislava", Location: "Slovakia"},
	}

	// Create a new HTTP multiplexer (mux).
	mux := http.NewServeMux()

	// Define handler for "/cities" endpoint.
	mux.HandleFunc("/cities", func(w http.ResponseWriter, r *http.Request) {
		enc := json.NewEncoder(w)
		if r.Method == http.MethodGet {
			// Handle GET request: Return the list of cities.
			enc.Encode(cities)
		} else if r.Method == http.MethodPost {
			// Handle POST request: Add a new city to the list.
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			r.Body.Close()

			// Decode the incoming JSON data into a City object.
			city := City{}
			if err := json.Unmarshal(data, &city); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Assign a new ID (incremental) to the new city.
			city.ID = strconv.Itoa(len(cities) + 1)

			// Append the new city to the list of cities.
			cities = append(cities, city)

			// Return the newly added city as a JSON response.
			enc.Encode(city)
		}
	})

	// Create and return an HTTP server configured with the multiplexer (mux).
	return http.Server{
		Addr:    addr,
		Handler: mux,
	}
}










/*
Package main demonstrates how to send an email using SMTP with authentication and TLS encryption in Go.

This program prompts the user for SMTP credentials (username and password), establishes a connection to Gmail's SMTP server,
and sends a simple email message using the provided credentials.
*/
package main

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

func main() {
	// Prompt the user to enter SMTP username (email address).
	var email string
	fmt.Println("Enter username for smtp: ")
	fmt.Scanln(&email)

	// Prompt the user to enter SMTP password.
	var pass string
	fmt.Println("Enter password for smtp: ")
	fmt.Scanln(&pass)

	// Authenticate using PlainAuth with the provided credentials.
	auth := smtp.PlainAuth("",
		email,
		pass,
		"smtp.gmail.com")

	// Connect to Gmail's SMTP server on port 587 (TLS encryption).
	c, err := smtp.Dial("smtp.gmail.com:587")
	if err != nil {
		panic(err)
	}
	defer c.Close()

	// Enable TLS encryption on the SMTP connection.
	config := &tls.Config{ServerName: "smtp.gmail.com"}
	if err = c.StartTLS(config); err != nil {
		panic(err)
	}

	// Authenticate with the server using the provided credentials.
	if err = c.Auth(auth); err != nil {
		panic(err)
	}

	// Set the sender's email address.
	if err = c.Mail(email); err != nil {
		panic(err)
	}

	// Set the recipient's email address (same as sender in this example).
	if err = c.Rcpt(email); err != nil {
		panic(err)
	}

	// Open a data connection to send the email content.
	w, err := c.Data()
	if err != nil {
		panic(err)
	}

	// Define the email message content (in this case, a simple text message).
	msg := []byte("Hello, this is the email content")

	// Write the message content to the data connection.
	if _, err := w.Write(msg); err != nil {
		panic(err)
	}

	// Close the data connection.
	err = w.Close()
	if err != nil {
		panic(err)
	}

	// Quit the SMTP session.
	err = c.Quit()
	if err != nil {
		panic(err)
	}
}










/*
Package main demonstrates how to set up a simple RPC server and client using net/rpc and net/rpc/jsonrpc packages in Go.

This program defines a simple RPC server that exposes an Add method, which adds two integers received in Args struct
and returns the result in Result struct. The client connects to this server using JSON-RPC over TCP, sends an Add RPC
request, and prints the result received from the server.
*/
package main

import (
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

// Args represents the arguments for the Add method.
type Args struct {
	A, B int
}

// Result represents the result of the Add method.
type Result int

// RpcServer represents the RPC server type.
type RpcServer struct{}

// Add is an RPC method on RpcServer that adds two integers.
func (t RpcServer) Add(args *Args, result *Result) error {
	log.Printf("Adding %d to %d\n", args.A, args.B)
	*result = Result(args.A + args.B)
	return nil
}

// addr represents the address and port on which the RPC server listens.
const addr = ":7070"

func main() {
	// Start the RPC server in a separate goroutine.
	go createServer(addr)

	// Connect to the RPC server using JSON-RPC over TCP.
	client, err := jsonrpc.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// Prepare arguments for the RPC call.
	args := &Args{
		A: 2,
		B: 3,
	}
	var result Result

	// Call the Add method on the RPC server.
	err = client.Call("RpcServer.Add", args, &result)
	if err != nil {
		log.Fatalf("Error calling RpcServer.Add: %s", err)
	}

	// Print the result received from the RPC server.
	log.Printf("%d + %d = %d\n", args.A, args.B, result)
}

// createServer creates and starts an RPC server that listens for incoming connections on the specified address.
func createServer(addr string) {
	// Create a new RPC server instance.
	server := rpc.NewServer()

	// Register the RpcServer type to handle RPC requests.
	err := server.Register(RpcServer{})
	if err != nil {
		panic(err)
	}

	// Listen for incoming TCP connections on the specified address.
	l, e := net.Listen("tcp", addr)
	if e != nil {
		log.Fatalf("Couldn't start listening on %s: %s", addr, e)
	}

	// Accept incoming connections and serve RPC requests using JSON-RPC codec.
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go server.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}



















/*
Package main demonstrates how to connect to a PostgreSQL database using the "database/sql" package and the pq driver in Go.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It verifies the connection by pinging the database and prints "Ping OK"
if the connection is successful.
*/
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import the PostgreSQL driver package anonymously
)

func main() {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	// Print message indicating successful ping
	fmt.Println("Ping OK")
}










/*
Package main demonstrates how to use PostgreSQL database connection and context handling with "database/sql" package and the pq driver in Go.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It verifies the connection by performing pings with and without a context.
It also demonstrates creating a connection using db.Conn() and verifying its ping using a context.

Note: The use of time.Nanosecond for context timeout is not practical and is only used here to demonstrate context handling.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432.

init.sql:
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
*/
package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

func main() {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Ping OK.")

	// Create a context with a timeout of 1 nanosecond (not practical, for demonstration purposes only)
	ctx, _ := context.WithTimeout(context.Background(), time.Nanosecond)

	// Ping the database with the context
	err = db.PingContext(ctx)
	if err != nil {
		fmt.Println("Error: " + err.Error())
	}

	// Create a connection using db.Conn()
	conn, err := db.Conn(context.Background())
	if err != nil {
		panic(err)
	}
	defer conn.Close() // Ensure the connection is closed when function exits

	// Ping the connection with a context
	err = conn.PingContext(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println("Connection Ping OK.")
}










/*
Package main demonstrates basic CRUD operations (Create, Read, Update, Delete) with PostgreSQL using Go's database/sql package and the pq driver.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Truncates the "post" table.
- Inserts predefined rows into the "post" table.
- Selects and counts the number of rows in the "post" table.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.

*/
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

// SQL statements for database operations
const (
	sel   = "SELECT * FROM post;"                                     // Select all rows from "post" table
	trunc = "TRUNCATE TABLE post;"                                     // Truncate (empty) "post" table
	ins   = "INSERT INTO post(ID,TITLE,CONTENT) VALUES (1,'Title 1','Content 1'), (2,'Title 2','Content 2');" // Insert rows into "post" table
)

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Truncate the "post" table
	_, err := db.Exec(trunc)
	if err != nil {
		panic(err)
	}
	fmt.Println("Table truncated.")

	// Insert rows into the "post" table
	r, err := db.Exec(ins)
	if err != nil {
		panic(err)
	}
	affected, err := r.RowsAffected()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Inserted rows count: %d\n", affected)

	// Query and count rows from the "post" table
	rs, err := db.Query(sel)
	if err != nil {
		panic(err)
	}
	count := 0
	for rs.Next() {
		if rs.Err() != nil {
			fmt.Println(rs.Err())
			continue
		}
		count++
	}
	fmt.Printf("Total of %d rows selected.\n", count)
}

// createConnection establishes a connection to the PostgreSQL database and returns the *sql.DB object.
func createConnection() *sql.DB {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}










/*
Package main demonstrates how to perform batch insert operations into a PostgreSQL database table using prepared statements with Go's database/sql package and the pq driver.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Truncates the "post" table to clear existing data.
- Uses a prepared statement to insert multiple rows into the "post" table from a predefined slice of structs.
- Prints the number of rows successfully inserted.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.


init.sql:
DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
*/
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

// SQL statements for database operations
const (
	trunc = "TRUNCATE TABLE post;"                        // Truncate (empty) "post" table
	ins   = "INSERT INTO post(ID,TITLE,CONTENT) VALUES ($1,$2,$3)" // Insert statement with placeholders
)

// Struct for test data
var testTable = []struct {
	ID      int
	Title   string
	Content string
}{
	{1, "Title One", "Content of title one"},
	{2, "Title Two", "Content of title two"},
	{3, "Title Three", "Content of title three"},
}

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Truncate the "post" table
	_, err := db.Exec(trunc)
	if err != nil {
		panic(err)
	}
	fmt.Println("Table truncated.")

	// Prepare the insert statement
	stm, err := db.Prepare(ins)
	defer stm.Close() // Ensure the prepared statement is closed
	if err != nil {
		panic(err)
	}

	inserted := int64(0)
	// Iterate over testTable and insert rows using the prepared statement
	for _, val := range testTable {
		fmt.Printf("Inserting record ID: %d\n", val.ID)
		// Execute the prepared statement with values from the struct
		r, err := stm.Exec(val.ID, val.Title, val.Content)
		if err != nil {
			fmt.Printf("Cannot insert record ID : %d\n", val.ID)
		}
		// Retrieve the number of affected rows and accumulate the total
		if affected, err := r.RowsAffected(); err == nil {
			inserted += affected
		}
	}

	// Print the total number of rows successfully inserted
	fmt.Printf("Result: Inserted %d rows.\n", inserted)
}

// createConnection establishes a connection to the PostgreSQL database and returns the *sql.DB object.
func createConnection() *sql.DB {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}










/*
Package main demonstrates executing a large SQL query with context timeout using Go's database/sql package and the pq driver for PostgreSQL.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Creates a database connection.
- Uses a context with a timeout of 20 microseconds to limit the query execution time.
- Executes a SELECT query (`sel`) that performs a cross join with a large series to generate a significant number of rows.
- Cancels the query if it exceeds the context timeout.
- Prints the number of rows returned by the query.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.
- Adjust the context timeout (`20*time.Microsecond`) as needed for your query's expected execution time.


init.sql:
DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,'Title Two','Content Two');
*/
package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

// SQL SELECT statement to generate a large number of rows
const sel = "SELECT * FROM post p CROSS JOIN (SELECT 1 FROM generate_series(1,1000000)) tbl"

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Create a context with a timeout of 20 microseconds
	ctx, canc := context.WithTimeout(context.Background(), 20*time.Microsecond)
	defer canc() // Ensure the cancellation function is called to cancel the query if it exceeds the timeout

	// Execute the query with context timeout
	rows, err := db.QueryContext(ctx, sel)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	// Count the number of rows returned by the query
	count := 0
	for rows.Next() {
		if rows.Err() != nil {
			fmt.Println(rows.Err())
			continue
		}
		count++
	}

	// Print the number of rows returned
	fmt.Printf("%d rows returned\n", count)
}

// createConnection establishes a connection to the PostgreSQL database and returns the *sql.DB object.
func createConnection() *sql.DB {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}










/*
Package main demonstrates querying PostgreSQL database for column information using Go's database/sql package and the pq driver.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Creates a database connection.
- Executes a SELECT query (`sel`) to fetch all columns from the "post" table.
- Retrieves and prints information about the selected columns, including their names, types, and other properties.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.


init.sql:
DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,'Title Two','Content Two');
*/
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

// SQL SELECT statement to fetch all columns from the "post" table
const sel = "SELECT * FROM post p"

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Execute the SELECT query to fetch all columns
	rs, err := db.Query(sel)
	if err != nil {
		panic(err)
	}
	defer rs.Close()

	// Retrieve and print the selected column names
	columns, err := rs.Columns()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Selected columns: %v\n", columns)

	// Retrieve and print information about each column type
	colTypes, err := rs.ColumnTypes()
	if err != nil {
		panic(err)
	}
	for _, col := range colTypes {
		fmt.Println()
		fmt.Printf("%+v\n", col)
	}
}

// createConnection establishes a connection to the PostgreSQL database and returns the *sql.DB object.
func createConnection() *sql.DB {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}










/*
Package main demonstrates querying PostgreSQL database for multiple result sets and single row using Go's database/sql package and the pq driver.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Creates a database connection.
- Executes multiple SELECT queries (`sel` and `selOne`) to fetch multiple result sets and a single row.
- Retrieves and prints the selected posts and number.
- Handles errors gracefully using panic and printing error messages.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Update connStr with your PostgreSQL database connection details.
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.


init.sql:
DROP TABLE IF EXISTS post;
       CREATE TABLE post (
         ID serial,
         TITLE varchar(40),
         CONTENT varchar(255),
         CONSTRAINT pk_post PRIMARY KEY(ID)
       );
       SELECT * FROM post;
       INSERT INTO post(ID,TITLE,CONTENT) VALUES
                       (1,'Title One','Content One'),
                       (2,NULL,'Content Two');
*/

package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // Import PostgreSQL driver package anonymously
)

// SQL SELECT statement to fetch title and content from the "post" table and a constant number
const sel = `SELECT title,content FROM post;
			SELECT 1234 NUM;`

// SQL SELECT statement to fetch title and content from the "post" table based on ID parameter
const selOne = "SELECT title,content FROM post WHERE ID = $1;"

// Post struct represents a row from the "post" table
type Post struct {
	Name sql.NullString
	Text sql.NullString
}

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Execute the first SELECT query (`sel`) to fetch multiple result sets
	rs, err := db.Query(sel)
	if err != nil {
		panic(err)
	}
	defer rs.Close()

	// Retrieve and store posts from the first result set
	posts := []Post{}
	for rs.Next() {
		p := Post{}
		if err := rs.Scan(&p.Name, &p.Text); err != nil {
			panic(err)
		}
		posts = append(posts, p)
	}

	// Move to the next result set to retrieve the number
	var num int
	if rs.NextResultSet() {
		for rs.Next() {
			if err := rs.Scan(&num); err != nil {
				panic(err)
			}
		}
	}

	// Print retrieved posts and number
	fmt.Printf("Retrieved posts: %+v\n", posts)
	fmt.Printf("Retrieved number: %d\n", num)

	// Execute the second SELECT query (`selOne`) to fetch a single row based on ID parameter
	row := db.QueryRow(selOne, 100)
	or := Post{}
	if err := row.Scan(&or.Name, &or.Text); err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return
	}

	// Print retrieved single post
	fmt.Printf("Retrieved one post: %+v\n", or)
}

// createConnection establishes a connection to the PostgreSQL database and returns the *sql.DB object.
func createConnection() *sql.DB {
	// Connection string for PostgreSQL database
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"

	// Open a connection to the PostgreSQL database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return db
}










/*
Package main demonstrates querying a PostgreSQL database using Go's database/sql package and the pq driver. It retrieves a specific row from the "post" table based on the ID and demonstrates two methods to parse the result set into a map.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Queries a single row from the "post" table based on ID = 1.
- Parses the result set using both RawBytes and standard interface{} methods.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.


init.sql:
DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES 
                        (1,NULL,'Content One'),
                        (2,'Title Two','Content Two');
*/
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// selOne is the SQL statement to select a specific row from the "post" table by ID.
const selOne = "SELECT id,title,content FROM post WHERE ID = $1;"

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close() // Ensure the database connection is closed when main function exits

	// Query the specific row from the "post" table based on ID = 1
	rows, err := db.Query(selOne, 1)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	// Get column names from the result set
	cols, _ := rows.Columns()

	// Iterate over the result set
	for rows.Next() {
		// Parse the row into a map using RawBytes method
		m := parseWithRawBytes(rows, cols)
		fmt.Println("Parsed with RawBytes:", m)

		// Parse the row into a map using standard interface{} method
		m = parseToMap(rows, cols)
		fmt.Println("Parsed with interface{}:", m)
	}
}

// parseWithRawBytes parses a row from sql.Rows into a map[string]interface{} using RawBytes method.
func parseWithRawBytes(rows *sql.Rows, cols []string) map[string]interface{} {
	vals := make([]sql.RawBytes, len(cols))
	scanArgs := make([]interface{}, len(vals))
	for i := range vals {
		scanArgs[i] = &vals[i]
	}
	if err := rows.Scan(scanArgs...); err != nil {
		panic(err)
	}
	m := make(map[string]interface{})
	for i, col := range vals {
		if col == nil {
			m[cols[i]] = nil
		} else {
			m[cols[i]] = string(col)
		}
	}
	return m
}

// parseToMap parses a row from sql.Rows into a map[string]interface{} using standard interface{} method.
func parseToMap(rows *sql.Rows, cols []string) map[string]interface{} {
	values := make([]interface{}, len(cols))
	pointers := make([]interface{}, len(cols))
	for i := range values {
		pointers[i] = &values[i]
	}

	if err := rows.Scan(pointers...); err != nil {
		panic(err)
	}

	m := make(map[string]interface{})
	for i, colName := range cols {
		if values[i] == nil {
			m[colName] = nil
		} else {
			m[colName] = values[i]
		}
	}
	return m
}

// createConnection establishes a connection to the PostgreSQL database and returns the connection object.
func createConnection() *sql.DB {
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected to PostgreSQL!")
	return db
}










/*
Package main demonstrates transaction management in PostgreSQL using Go's database/sql package and the pq driver. It showcases how to perform operations inside transactions, including querying and modifying data, rolling back transactions, and using contexts for transaction control.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Starts a transaction and inserts a new row into the "post" table.
- Queries the newly inserted row both outside and within the transaction.
- Rolls back the transaction to discard changes.
- Demonstrates a transaction with context, showing how to use contexts to control transaction lifespan and ensure proper cleanup.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go

Usage:
- Ensure PostgreSQL server is running on localhost:5432 and the "post" table exists in the "example" database.


init.sql:
DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,NULL,'Content Two');
*/
package main

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// selOne is the SQL statement to select a specific row from the "post" table by ID.
const selOne = "SELECT id,title,content FROM post WHERE ID = $1;"

// insert is the SQL statement to insert a new row into the "post" table.
const insert = "INSERT INTO post(ID,TITLE,CONTENT) VALUES (4,'Transaction Title','Transaction Content');"

// Post represents the structure of a post entity.
type Post struct {
	ID      int
	Title   string
	Content string
}

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close()

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		panic(err)
	}

	// Insert a new row into the "post" table within the transaction
	_, err = tx.Exec(insert)
	if err != nil {
		panic(err)
	}

	// Query the newly inserted row from a separate session (outside transaction)
	p := Post{}
	if err := db.QueryRow(selOne, 4).Scan(&p.ID, &p.Title, &p.Content); err != nil {
		fmt.Println("Error querying outside transaction:", err)
	}
	fmt.Println("Query outside transaction:", p)

	// Query the newly inserted row from within the transaction
	if err := tx.QueryRow(selOne, 4).Scan(&p.ID, &p.Title, &p.Content); err != nil {
		fmt.Println("Error querying within transaction:", err)
	}
	fmt.Println("Query within transaction:", p)

	// Rollback the transaction to discard changes
	err = tx.Rollback()
	if err != nil {
		panic(err)
	}
	fmt.Println("Transaction rolled back successfully.")

	// Demonstrate transaction with context
	fmt.Println("\nTransaction with context")
	ctx, cancel := context.WithCancel(context.Background())
	tx, err = db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadUncommitted})
	if err != nil {
		panic(err)
	}

	// Insert a new row into the "post" table within the transaction
	_, err = tx.Exec(insert)
	if err != nil {
		panic(err)
	}

	// Cancel the context to simulate premature transaction termination
	cancel()

	// Commit the transaction (which should fail due to canceled context)
	err = tx.Commit()
	if err != nil {
		fmt.Println("Error committing transaction with canceled context:", err)
	}
}

// createConnection establishes a connection to the PostgreSQL database and returns the connection object.
func createConnection() *sql.DB {
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected to PostgreSQL!")
	return db
}










/*
Package main demonstrates calling stored procedures/functions in both PostgreSQL and MySQL databases using Go's database/sql package and respective drivers.

This program connects to a local PostgreSQL database named "example" running on port 5432 with the username and password "postgres".
It disables SSL mode for simplicity in local development. It performs the following operations:
- Calls a PostgreSQL function named format_name with three parameters and retrieves the result.

Dependencies:
- github.com/lib/pq: PostgreSQL driver for Go
- github.com/go-sql-driver/mysql: MySQL driver for Go

Usage:
- Ensure PostgreSQL server is running on localhost:5432 and the "example" database contains the format_name function.

init.sql:
CREATE OR REPLACE FUNCTION format_name
        (firstname Text,lastname Text,age INT) RETURNS 
        VARCHAR AS $$
        BEGIN
          RETURN trim(firstname) ||' '||trim(lastname) ||' ('||age||')';
        END;
        $$ LANGUAGE plpgsql;
*/

package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	_ "github.com/lib/pq"              // PostgreSQL driver
)

// call is the SQL statement to call the format_name function in PostgreSQL.
const call = "select * from format_name($1,$2,$3)"

// callMySQL is the SQL statement to call the simpleproc stored procedure in MySQL.
const callMySQL = "CALL simpleproc(?)"

// Result represents the structure of the result from calling the stored procedure/function.
type Result struct {
	Name     string
	Category int
}

func main() {
	// Create a database connection
	db := createConnection()
	defer db.Close()

	// Initialize a Result struct to hold the returned values
	r := Result{}

	// Call the PostgreSQL function format_name with parameters and scan the result into Result struct
	if err := db.QueryRow(call, "John", "Doe", 32).Scan(&r.Name); err != nil {
		panic(err)
	}
	fmt.Printf("Result is: %+v\n", r)
}

// createConnection establishes a connection to the PostgreSQL database and returns the connection object.
func createConnection() *sql.DB {
	connStr := "postgres://postgres:postgres@localhost:5432/example?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected to PostgreSQL!")
	return db
}




// This code implements a TCP server on port 8080 that accepts incoming connections,
// reads messages from clients, and responds with a confirmation message.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

func main() {

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	for {
		fmt.Println("Waiting for client...")
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}

		msg, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			panic(err)
		}
		_, err = io.WriteString(conn, "Received: "+string(msg))
		if err != nil {
			fmt.Println(err)
		}
		conn.Close()
	}

}




// This code sets up a UDP server on port 7070 that listens for incoming packets,
// reads messages from clients, and echoes back a confirmation message to the sender.
package main

import (
	"fmt"
	"log"
	"net"
)

func main() {

	pc, err := net.ListenPacket("udp", ":7070")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	buffer := make([]byte, 2048)
	fmt.Println("Waiting for client...")
	for {

		_, addr, err := pc.ReadFrom(buffer)
		if err == nil {
			rcvMsq := string(buffer)
			fmt.Println("Received: " + rcvMsq)
			if _, err := pc.WriteTo([]byte("Received: "+rcvMsq), addr); err != nil {
				fmt.Println("error on write: " + err.Error())
			}
		} else {
			fmt.Println("error: " + err.Error())
		}

	}

}



// This code establishes a TCP server on port 8080 that accepts incoming connections,
// assigns a unique client ID to each connection, sends a welcome message to clients,
// and echoes back received messages with a prefix indicating reception.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

func main() {

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	ID := 0
	for {
		fmt.Println("Waiting for client...")
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Client ID: %d connected.\n", ID)
		go func(c net.Conn, clientID int) {
			fmt.Fprintf(c, "Welcome client ID: %d \n", clientID)
			for {
				msg, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					fmt.Println(err)
					break
				}
				_, err = io.WriteString(c, "Received: "+string(msg))
				if err != nil {
					fmt.Println(err)
					break
				}
			}
			fmt.Println("Closing connection")
			c.Close()
		}(conn, ID)
		ID++
	}

}


// This code starts an HTTP server on port 8080 that responds with "Hello world" to incoming requests.
package main

import (
	"fmt"
	"net/http"
)

type SimpleHTTP struct{}

func (s SimpleHTTP) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(rw, "Hello world")
}

func main() {
	fmt.Println("Starting HTTP server on port 8080")
	s := &http.Server{Addr: ":8080", Handler: SimpleHTTP{}}
	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}


// This code sets up an HTTP server on port 8080 with multiple routes:
// - "/user" responds differently based on GET and POST methods.
// - "/items/clothes" serves "Clothes" using a separate mux under "/items/".
// - "/admin/ports" serves "Ports" using a mux under "/admin/" with prefix stripping.
package main

import (
	"fmt"
	"net/http"
)

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprintln(w, "User GET")
		}
		if r.Method == http.MethodPost {
			fmt.Fprintln(w, "User POST")
		}
	})

	// separate handler
	itemMux := http.NewServeMux()
	itemMux.HandleFunc("/items/clothes", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Clothes")
	})
	mux.Handle("/items/", itemMux)

	// Admin handlers
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/ports", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Ports")
	})

	mux.Handle("/admin/",
		http.StripPrefix("/admin", adminMux))

	// Default server
	http.ListenAndServe(":8080", mux)

}


// This code sets up an HTTP server on port 8080 with two protected endpoints:
// - "/api/users" returns a JSON array of users.
// - "/api/profile" requires authentication via "X-Auth" header and includes a user profile JSON response.
package main

import (
	"io"
	"log"
	"net/http"
)

type User string

func (u User) toString() string {
	return string(u)
}

type AuthHandler func(u User, w http.ResponseWriter, r *http.Request)

func main() {

	// Secured API
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", Secure(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w,
			`[{"id":"1","login":"ffghi"},{"id":"2","login":"ffghj"}]`)
	}))
	mux.HandleFunc("/api/profile", WithUser(func(u User, w http.ResponseWriter, r *http.Request) {
		log.Println(u.toString())
		io.WriteString(w, "{\"user\":\""+u.toString()+"\"}")
	}))

	http.ListenAndServe(":8080", mux)

}

func WithUser(h AuthHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		if len(user) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(User(user), w, r)
	}
}

func Secure(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sec := r.Header.Get("X-Auth")
		if sec != "authenticated" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r) // use the handler
	}
}


// This code sets up an HTTP server on port 8080:
// - "/welcome" serves the content of "welcome.txt" file.
// - "/html/" serves static files from the "html" directory, stripping "/html" prefix.
package main

import (
	"net/http"
)

func main() {

	fileSrv := http.FileServer(http.Dir("html"))
	fileSrv = http.StripPrefix("/html", fileSrv)

	http.HandleFunc("/welcome", serveWelcome)
	http.Handle("/html/", fileSrv)
	http.ListenAndServe(":8080", nil)
}

func serveWelcome(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "welcome.txt")
}


// This code starts an HTTP server on port 8080 that renders a template file "template.tpl"
// and serves it when accessing the root ("/") endpoint.
package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func main() {
	fmt.Println("Server is starting...")
	tpl, err := template.ParseFiles("template.tpl")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := tpl.Execute(w, "John Doe")
		if err != nil {
			panic(err)
		}
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}


// This code starts an HTTP server on port 8080 with three endpoints:
// - "/secured/handle" redirects using http.RedirectHandler to "/login".
// - "/secured/hadlefunc" redirects using http.Redirect to "/login".
// - "/login" responds with a message "Welcome user! Please login!".
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	log.Println("Server is starting...")

	http.Handle("/secured/handle", http.RedirectHandler("/login", http.StatusTemporaryRedirect))
	http.HandleFunc("/secured/hadlefunc", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome user! Please login!\n")
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}


// This code starts an HTTP server on port 8080 with three endpoints:
// - "/set" sets a cookie named "X-Cookie" with value "Go is awesome." and domain "localhost".
// - "/get" retrieves and displays the value of the "X-Cookie" cookie and lists all cookies sent with the request.
// - "/remove" removes the "X-Cookie" cookie by setting its MaxAge to -1.
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

const cookieName = "X-Cookie"

func main() {
	log.Println("Server is starting...")

	http.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		c := &http.Cookie{
			Name:    cookieName,
			Value:   "Go is awesome.",
			Expires: time.Now().Add(time.Hour),
			Domain:  "localhost",
		}
		http.SetCookie(w, c)
		fmt.Fprintln(w, "Cookie is set!")
	})
	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		val, err := r.Cookie(cookieName)
		if err != nil {
			fmt.Fprintln(w, "Cookie err: "+err.Error())
			return
		}
		fmt.Fprintf(w, "Cookie is: %s \n", val.Value)
		fmt.Fprintf(w, "Other cookies:\n")
		for _, v := range r.Cookies() {
			fmt.Fprintf(w, "%s => %s \n", v.Name, v.Value)
		}
	})
	http.HandleFunc("/remove", func(w http.ResponseWriter, r *http.Request) {
		val, err := r.Cookie(cookieName)
		if err != nil {
			fmt.Fprintln(w, "Cookie err: "+err.Error())
			return
		}
		val.MaxAge = -1
		http.SetCookie(w, val)
		fmt.Fprintln(w, "Cookie is removed!")
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}


// This code starts an HTTP server on port 8080 that responds with "Hello world!" after a delay.
// It handles graceful shutdown using OS signals (SIGINT) to stop the server and waits up to 30 seconds for connections to close.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		fmt.Fprintln(w, "Hello world!")
	})

	srv := &http.Server{Addr: ":8080", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("Server error: %s\n", err)
		}
	}()

	log.Println("Server listening on : " + srv.Addr)

	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	<-stopChan // wait for SIGINT
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	log.Println("Server gracefully stopped")
}



// This code starts an HTTPS server on port 8080 using TLS certificates "server.crt" and "server.key",
// with a handler that responds with "Hello world".
package main

import (
	"fmt"
	"net/http"
)

type SimpleHTTP struct{}

func (s SimpleHTTP) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(rw, "Hello world")
}

func main() {
	fmt.Println("Starting HTTPS server on port 8080")
	s := &http.Server{Addr: ":8080", Handler: SimpleHTTP{}}
	if err := s.ListenAndServeTLS("server.crt", "server.key"); err != nil {
		panic(err)
	}
}



// This code defines an HTTP server that responds with "Hello world" and demonstrates handling form data:
// - It logs the request form data before and after calling req.ParseForm().
// - It prints the value of "param1" from the parsed form.
// - It serves "Hello world" as the response to any incoming request.
package main

import (
	"fmt"
	"net/http"
)

type StringServer string

func (s StringServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	fmt.Printf("Prior ParseForm: %v\n", req.Form)
	req.ParseForm()
	fmt.Printf("Post ParseForm: %v\n", req.Form)
	fmt.Println("Param1 is : " + req.Form.Get("param1"))
	fmt.Printf("PostForm : %v\n", req.PostForm)
	rw.Write([]byte(string(s)))
}

func createServer(addr string) http.Server {
	return http.Server{
		Addr:    addr,
		Handler: StringServer("Hello world"),
	}
}

func main() {
	s := createServer(":8080")
	fmt.Println("Server is starting...")
	if err := s.ListenAndServe(); err != nil {
		panic(err)
	}
}


// This code demonstrates the usage of a thread-safe synchronized list (SyncList) with mutex protection,
// allowing concurrent goroutines to safely append and retrieve values, ensuring data integrity.
package main

import (
	"fmt"
	"sync"
)

var names = []string{"Alan", "Joe", "Jack", "Ben",
	"Ellen", "Lisa", "Carl", "Steve", "Anton", "Yo"}

type SyncList struct {
	m     sync.Mutex
	slice []interface{}
}

func NewSyncList(cap int) *SyncList {
	return &SyncList{
		sync.Mutex{},
		make([]interface{}, cap),
	}
}

func (l *SyncList) Load(i int) interface{} {
	l.m.Lock()
	defer l.m.Unlock()
	return l.slice[i]
}

func (l *SyncList) Append(val interface{}) {
	l.m.Lock()
	defer l.m.Unlock()
	l.slice = append(l.slice, val)
}

func (l *SyncList) Store(i int, val interface{}) {
	l.m.Lock()
	defer l.m.Unlock()
	l.slice[i] = val
}

func main() {

	l := NewSyncList(0)
	wg := &sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			l.Append(names[idx])
			wg.Done()
		}(i)
	}
	wg.Wait()

	for i := 0; i < 10; i++ {
		fmt.Printf("Val: %v stored at idx: %d\n", l.Load(i), i)
	}

}

// This code demonstrates the usage of sync.Map for concurrent-safe access to a map,
// storing and retrieving values with goroutines, and utilizing Load, LoadOrStore, and Range methods.
package main

import (
	"fmt"
	"sync"
)

var names = []string{"Alan", "Joe", "Jack", "Ben",
	"Ellen", "Lisa", "Carl", "Steve", "Anton", "Yo"}

func main() {

	m := sync.Map{}
	wg := sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			m.Store(fmt.Sprintf("%d", idx), names[idx])
			wg.Done()
		}(i)
	}
	wg.Wait()

	v, ok := m.Load("1")
	if ok {
		fmt.Printf("For Load key: 1 got %v\n", v)
	}

	v, ok = m.LoadOrStore("11", "Tim")
	if !ok {
		fmt.Printf("Key 11 missing stored val: %v\n", v)
	}

	m.Range(func(k, v interface{}) bool {
		key, _ := k.(string)
		t, _ := v.(string)
		fmt.Printf("For index %v got %v\n", key, t)
		return true
	})

}



// This code defines a Source type with a Pop method that ensures data loading occurs only once,
// simulating a delayed initialization of data with sync.Mutex and sync.Once synchronization mechanisms,
// and demonstrates concurrent access to the Pop method by multiple goroutines.
package main

import (
	"fmt"
	"sync"
	"time"
)

var names = []interface{}{"Alan", "Joe", "Jack", "Ben",
	"Ellen", "Lisa", "Carl", "Steve", "Anton", "Yo"}

type Source struct {
	m    *sync.Mutex
	o    *sync.Once
	data []interface{}
}

func (s *Source) Pop() (interface{}, error) {
	s.m.Lock()
	defer s.m.Unlock()
	s.o.Do(func() {
		time.Sleep(time.Second * 30) // Simulates data loading delay
		s.data = names
		fmt.Println("Data has been loaded.")
	})
	if len(s.data) > 0 {
		res := s.data[0]
		s.data = s.data[1:]
		return res, nil
	}
	return nil, fmt.Errorf("No data available")
}

func main() {

	s := &Source{&sync.Mutex{}, &sync.Once{}, nil}
	wg := sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			if val, err := s.Pop(); err == nil {
				fmt.Printf("Pop %d returned: %s\n", idx, val)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}




// This program demonstrates the usage of sync.Pool to manage a pool of Worker objects,
// allowing efficient reuse of objects across multiple goroutines with minimized memory allocations.
package main

import (
	"fmt"
	"sync"
	"time"
)

type Worker struct {
	id string
}

func (w *Worker) String() string {
	return w.id
}

var globalCounter = 0

var pool = sync.Pool{
	New: func() interface{} {
		res := &Worker{fmt.Sprintf("%d", globalCounter)}
		globalCounter++
		return res
	},
}

func main() {
	wg := sync.WaitGroup{}
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			w := pool.Get().(*Worker) // Get a worker from the pool
			fmt.Println("Got worker ID: " + w.String())
			time.Sleep(time.Second) // Simulate work with the worker
			pool.Put(w)             // Put the worker back into the pool
			wg.Done()
		}(i)
	}
	wg.Wait()
}



// This code demonstrates the usage of sync.WaitGroup to synchronize and wait for a group of goroutines to complete,
// each printing an exit message with its index before signaling completion.
package main

import (
	"fmt"
	"sync"
)

func main() {
	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			// Do some work
			defer wg.Done()
			fmt.Printf("Exiting %d\n", idx)
		}(i)
	}
	wg.Wait()
	fmt.Println("All done.")
}



// This program demonstrates concurrent searches from multiple sources (SearchSrc),
// using contexts to manage cancellation and merging results into a single channel.
package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type SearchSrc struct {
	ID    string
	Delay int
}

func (s *SearchSrc) Search(ctx context.Context) <-chan string {
	out := make(chan string)
	go func() {
		time.Sleep(time.Duration(s.Delay) * time.Second)
		select {
		case out <- "Result " + s.ID:
		case <-ctx.Done():
			fmt.Println("Search received Done()")
		}
		close(out)
		fmt.Println("Search finished for ID: " + s.ID)
	}()
	return out
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	src1 := &SearchSrc{"1", 2}
	src2 := &SearchSrc{"2", 6}

	r1 := src1.Search(ctx)
	r2 := src2.Search(ctx)

	out := merge(ctx, r1, r2)

	for firstResult := range out {
		cancel() // Cancel context after receiving the first result
		fmt.Println("First result is: " + firstResult)
	}
}

func merge(ctx context.Context, results ...<-chan string) <-chan string {
	wg := sync.WaitGroup{}
	out := make(chan string)

	output := func(c <-chan string) {
		defer wg.Done()
		select {
		case <-ctx.Done():
			fmt.Println("Received ctx.Done()")
		case res := <-c:
			out <- res
		}
	}

	wg.Add(len(results))
	for _, c := range results {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}


// This program detects errors in each line of the provided data using goroutines managed by errgroup,
// reporting any lines containing the substring "error:" as errors.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"strings"

	"golang.org/x/sync/errgroup"
)

const data = `line one
line two with more words
error: This is erroneous line`

func main() {
	log.Printf("Application %s starting.", "Error Detection")
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Split(bufio.ScanLines)

	// Use errgroup to manage multiple goroutines and errors
	g, _ := errgroup.WithContext(context.Background())
	for scanner.Scan() {
		row := scanner.Text()
		g.Go(func() error {
			if strings.Contains(row, "error:") {
				return fmt.Errorf("Error detected: %s", row)
			}
			return nil
		})
	}

	// Wait for all goroutines to complete and check for any errors
	if err := g.Wait(); err != nil {
		fmt.Println("Error while waiting: " + err.Error())
	}
}










package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAssertEquality(t *testing.T) {
	// Test case setup
	expected := 42
	actual := someFunctionReturning42()

	// Assertion
	assert.Equal(t, expected, actual, "they should be equal")
}

func someFunctionReturning42() int {
	return 42
}




package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorAssertion(t *testing.T) {
	// Test case setup
	err := errors.New("error message")

	// Assertion
	assert.Error(t, err, "error expected")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNilAssertion(t *testing.T) {
	// Test case setup
	var str *string

	// Assertion
	assert.Nil(t, str, "expected nil")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceAssertion(t *testing.T) {
	// Test case setup
	expected := []int{1, 2, 3}
	actual := []int{1, 2, 3}

	// Assertion
	assert.ElementsMatch(t, expected, actual, "slices should match")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapAssertion(t *testing.T) {
	// Test case setup
	expected := map[string]int{"a": 1, "b": 2}
	actual := map[string]int{"a": 1, "b": 2}

	// Assertion
	assert.Equal(t, expected, actual, "maps should be equal")
}





package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConcurrentOperation(t *testing.T) {
	// Test case setup
	ch := make(chan bool)

	go func() {
		// Simulate some operation
		time.Sleep(1 * time.Second)
		ch <- true
	}()

	// Assertion
	select {
	case <-ch:
		// Test passed
	case <-time.After(2 * time.Second):
		assert.Fail(t, "timed out")
	}
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"test1", test1},
		{"test2", test2},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}

func test1(t *testing.T) {
	assert.True(t, true, "true should be true")
}

func test2(t *testing.T) {
	assert.False(t, false, "false should be false")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPanicAssertion(t *testing.T) {
	// Test case setup
	fn := func() {
		panic("something went wrong")
	}

	// Assertion
	assert.Panics(t, fn, "function should panic")
}





package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONComparison(t *testing.T) {
	// Test case setup
	expectedJSON := `{"name": "John", "age": 30}`
	actualJSON := `{"age": 30, "name": "John"}`

	var expected, actual interface{}
	json.Unmarshal([]byte(expectedJSON), &expected)
	json.Unmarshal([]byte(actualJSON), &actual)

	// Assertion
	assert.JSONEq(t, expectedJSON, actualJSON, "JSON should match")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/mock"
)

type MyMockedObject struct {
	mock.Mock
}

func (m *MyMockedObject) DoSomething() bool {
	args := m.Called()
	return args.Bool(0)
}

func TestMocking(t *testing.T) {
	// Test case setup
	mockObj := new(MyMockedObject)
	mockObj.On("DoSomething").Return(true)

	// Assertion
	assert.True(t, mockObj.DoSomething(), "expected true")
	mockObj.AssertExpectations(t)
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFloatEquality(t *testing.T) {
	// Test case setup
	expected := 0.1 + 0.2
	actual := 0.3

	// Assertion
	assert.InDelta(t, expected, actual, 0.0001, "floats should be equal within delta")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Person struct {
	Name string
	Age  int
}

func TestStructAssertion(t *testing.T) {
	// Test case setup
	expected := Person{Name: "Alice", Age: 30}
	actual := Person{Name: "Alice", Age: 30}

	// Assertion
	assert.Equal(t, expected, actual, "structs should be equal")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceSubsetAssertion(t *testing.T) {
	// Test case setup
	expected := []int{1, 2, 3}
	actual := []int{1, 2, 3, 4, 5}

	// Assertion
	assert.Subset(t, actual, expected, "expected slice is a subset of actual slice")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegexMatching(t *testing.T) {
	// Test case setup
	actual := "Hello, World!"

	// Assertion
	assert.Regexp(t, "^Hello,.*$", actual, "string should match regex pattern")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringContains(t *testing.T) {
	// Test case setup
	actual := "Hello, World!"

	// Assertion
	assert.Contains(t, actual, "World", "string should contain substring")
}




package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileExists(t *testing.T) {
	// Test case setup
	filename := "example.txt"

	// Assertion
	assert.FileExists(t, filename, "file should exist")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLengthAssertion(t *testing.T) {
	// Test case setup
	slice := []int{1, 2, 3}

	// Assertion
	assert.Len(t, slice, 3, "slice should have length of 3")
}





package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func TestJSONMarshalling(t *testing.T) {
	// Test case setup
	user := User{Name: "Alice", Email: "alice@example.com"}
	expectedJSON := `{"name":"Alice","email":"alice@example.com"}`

	// Assertion
	actualJSON, err := json.Marshal(user)
	assert.NoError(t, err, "error marshalling JSON")
	assert.JSONEq(t, expectedJSON, string(actualJSON), "JSON should match")
}





package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeAssertion(t *testing.T) {
	// Test case setup
	expected := time.Date(2024, time.June, 25, 12, 0, 0, 0, time.UTC)
	actual := time.Now()

	// Assertion
	assert.WithinDuration(t, expected, actual, 1*time.Second, "time should be within 1 second")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkipAssertion(t *testing.T) {
	// Skip this test on certain conditions
	if shouldSkipTest {
		t.Skip("skipping test")
	}

	// Assertion
	assert.True(t, true, "this assertion should always pass")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Person struct {
	Name string
	Age  int
}

func TestDeepEquality(t *testing.T) {
	// Test case setup
	expected := Person{Name: "John", Age: 30}
	actual := Person{Name: "John", Age: 30}

	// Assertion
	assert.Equal(t, expected, actual, "persons should be deeply equal")
}





package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type User struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
}

func TestJSONMarshallingExcludeFields(t *testing.T) {
	// Test case setup
	user := User{Name: "Alice", Password: "secret"}
	expectedJSON := `{"name":"Alice"}`

	// Assertion
	actualJSON, err := json.Marshal(user)
	assert.NoError(t, err, "error marshalling JSON")
	assert.JSONEq(t, expectedJSON, string(actualJSON), "JSON should match (excluding password)")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapSubsetAssertion(t *testing.T) {
	// Test case setup
	expected := map[string]int{"a": 1, "b": 2}
	actual := map[string]int{"a": 1, "b": 2, "c": 3}

	// Assertion
	assert.Subset(t, actual, expected, "expected map is a subset of actual map")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetEquality(t *testing.T) {
	// Test case setup
	expected := []string{"apple", "banana", "cherry"}
	actual := []string{"banana", "cherry", "apple"}

	// Assertion
	assert.ElementsMatch(t, expected, actual, "sets should match")
}





package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeEquality(t *testing.T) {
	// Test case setup
	expected := time.Now()
	actual := expected.Add(1 * time.Second)

	// Assertion
	assert.WithinDuration(t, expected, actual, 1*time.Second, "times should be approximately equal")
}





package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestChannelOperations(t *testing.T) {
	// Test case setup
	ch := make(chan bool)

	go func() {
		time.Sleep(1 * time.Second)
		ch <- true
	}()

	// Assertion
	select {
	case <-ch:
		// Channel received value
	case <-time.After(2 * time.Second):
		assert.Fail(t, "timed out waiting for channel")
	}
}





package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPStatusCode(t *testing.T) {
	// Test case setup
	req, _ := http.NewRequest("GET", "/some-url", nil)
	recorder := httptest.NewRecorder()

	// Perform HTTP request
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler.ServeHTTP(recorder, req)

	// Assertion
	assert.Equal(t, http.StatusOK, recorder.Code, "HTTP status code should be 200")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockDB struct {
	mock.Mock
}

func (m *MockDB) Save(data interface{}) error {
	args := m.Called(data)
	return args.Error(0)
}

func TestDatabaseMocking(t *testing.T) {
	// Test case setup
	mockDB := new(MockDB)
	mockDB.On("Save", "testdata").Return(nil)

	// Assertion
	err := mockDB.Save("testdata")
	assert.NoError(t, err, "error should be nil")
	mockDB.AssertExpectations(t)
}





package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorMessage(t *testing.T) {
	// Test case setup
	expectedError := errors.New("expected error")

	// Function under test
	err := someFunctionReturningError()

	// Assertion
	assert.EqualError(t, err, expectedError.Error(), "error messages should match")
}

func someFunctionReturningError() error {
	return errors.New("expected error")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCustomAssertion(t *testing.T) {
	// Test case setup
	expected := 42
	actual := someFunctionReturning42()

	// Assertion using custom function
	assert.Condition(t, func() bool {
		return actual == expected
	}, "custom condition failed")
}

func someFunctionReturning42() int {
	return 42
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypeAssertion(t *testing.T) {
	// Test case setup
	var data interface{} = "hello"

	// Assertion
	assert.IsType(t, "", data, "data should be of type string")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type Writer interface {
	Write([]byte) (int, error)
}

type MockWriter struct{}

func (m *MockWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestImplementsInterfaceAssertion(t *testing.T) {
	// Test case setup
	var writer Writer = &MockWriter{}

	// Assertion
	assert.Implements(t, (*Writer)(nil), writer, "writer should implement Writer interface")
}





package main

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockCloser struct {
	closed bool
}

func (m *MockCloser) Close() error {
	m.closed = true
	return nil
}

func TestCloserInterfaceAssertion(t *testing.T) {
	// Test case setup
	mockCloser := &MockCloser{}

	// Assertion
	assert.NoError(t, mockCloser.Close(), "no error expected when closing")
	assert.True(t, mockCloser.closed, "close method should have been called")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPanicAssertion(t *testing.T) {
	// Test case setup
	fn := func() {
		panic("something went wrong")
	}

	// Assertion
	assert.Panics(t, fn, "function should panic")
}





package main

import (
	"bytes"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogOutputAssertion(t *testing.T) {
	// Test case setup
	var buf bytes.Buffer
	logger := log.New(&buf, "", log.Lshortfile)

	// Function under test
	logger.Print("hello")

	// Assertion
	assert.Contains(t, buf.String(), "hello", "log should contain expected output")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoErrorAssertion(t *testing.T) {
	// Test case setup
	err := someFunctionThatShouldNotError()

	// Assertion
	assert.NoError(t, err, "no error expected")
}

func someFunctionThatShouldNotError() error {
	return nil
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPointerEquality(t *testing.T) {
	// Test case setup
	expected := &struct{ Name string }{Name: "Alice"}
	actual := expected

	// Assertion
	assert.Same(t, expected, actual, "pointers should be the same")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotNilAssertion(t *testing.T) {
	// Test case setup
	str := "hello"

	// Assertion
	assert.NotNil(t, str, "string should not be nil")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZeroValueAssertion(t *testing.T) {
	// Test case setup
	var num int
	var str string
	var slice []int

	// Assertion
	assert.Zero(t, num, "num should be zero")
	assert.Zero(t, str, "str should be empty string")
	assert.Zero(t, slice, "slice should be nil")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrueFalseAssertion(t *testing.T) {
	// Test case setup
	value := true

	// Assertion
	assert.True(t, value, "value should be true")
	assert.False(t, !value, "value should be false")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComparisonAssertion(t *testing.T) {
	// Test case setup
	num1 := 10
	num2 := 5

	// Assertion
	assert.Greater(t, num1, num2, "num1 should be greater than num2")
	assert.Less(t, num2, num1, "num2 should be less than num1")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringContainsAssertion(t *testing.T) {
	// Test case setup
	str := "hello, world!"

	// Assertion
	assert.Contains(t, str, "world", "string should contain substring 'world'")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElementsMatchAssertion(t *testing.T) {
	// Test case setup
	expected := []int{1, 2, 3}
	actual := []int{1, 2, 3}

	// Assertion
	assert.Equal(t, expected, actual, "elements should match in order")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnorderedElementsMatchAssertion(t *testing.T) {
	// Test case setup
	expected := []int{1, 2, 3}
	actual := []int{3, 2, 1}

	// Assertion
	assert.ElementsMatch(t, expected, actual, "elements should match unordered")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceSubsetAssertion(t *testing.T) {
	// Test case setup
	expected := []int{1, 2, 3}
	actual := []int{1, 2, 3, 4, 5}

	// Assertion
	assert.Subset(t, actual, expected, "expected slice is a subset of actual slice")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapHasKeyAssertion(t *testing.T) {
	// Test case setup
	data := map[string]int{"a": 1, "b": 2}

	// Assertion
	assert.Contains(t, data, "a", "map should contain key 'a'")
	assert.Contains(t, data, "b", "map should contain key 'b'")
	assert.NotContains(t, data, "c", "map should not contain key 'c'")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConditionWithMessageAssertion(t *testing.T) {
	// Test case setup
	num := 10

	// Assertion
	assert.Condition(t, func() bool {
		return num > 5
	}, "num should be greater than 5")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyNotEmptyAssertion(t *testing.T) {
	// Test case setup
	var emptySlice []int
	notEmptySlice := []int{1, 2, 3}

	// Assertion
	assert.Empty(t, emptySlice, "empty slice should be empty")
	assert.NotEmpty(t, notEmptySlice, "non-empty slice should not be empty")
}





package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkipCondition(t *testing.T) {
	// Test case setup
	skipTest := true

	// Skip test if condition is met
	if skipTest {
		t.Skip("skipping test")
	}

	// Assertion
	assert.True(t, true, "this assertion should always pass")
}






package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCustomErrorAssertion(t *testing.T) {
	// Test case setup
	expectedError := errors.New("expected error")

	// Function under test
	err := someFunctionReturningCustomError()

	// Assertion
	assert.EqualError(t, err, expectedError.Error(), "error messages should match")
}

func someFunctionReturningCustomError() error {
	return errors.New("expected error")
}










package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Initialize Viper and set a default value for "key"
func main() {
	viper.SetDefault("key", "defaultValue")
	fmt.Println(viper.GetString("key"))  // Output: defaultValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Read configuration from a JSON file
func main() {
	viper.SetConfigName("config") // Name of the config file (without extension)
	viper.SetConfigType("json")   // Type of the config file
	viper.AddConfigPath(".")      // Path to look for the config file

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Read configuration from a YAML file
func main() {
	viper.SetConfigName("config") // Name of the config file (without extension)
	viper.SetConfigType("yaml")   // Type of the config file
	viper.AddConfigPath(".")      // Path to look for the config file

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Read configuration from a TOML file
func main() {
	viper.SetConfigName("config") // Name of the config file (without extension)
	viper.SetConfigType("toml")   // Type of the config file
	viper.AddConfigPath(".")      // Path to look for the config file

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Read configuration from environment variables
func main() {
	_ = os.Setenv("APP_KEY", "envValue")
	viper.BindEnv("key", "APP_KEY")

	fmt.Println(viper.GetString("key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration file path explicitly
func main() {
	viper.SetConfigFile("./config.yaml")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Check if a configuration key exists
func main() {
	viper.Set("key", "value")
	if viper.IsSet("key") {
		fmt.Println("Key exists")
	} else {
		fmt.Println("Key does not exist")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Watch for changes in the configuration file
func main() {
	viper.SetConfigFile("./config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
	})

	for {
		time.Sleep(time.Second)
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Unmarshal configuration into a struct
type Config struct {
	Key string
}

func main() {
	viper.SetConfigFile("./config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		panic(err)
	}

	fmt.Println(config.Key)
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Read configuration from command-line flags
func main() {
	key := flag.String("key", "default", "The key value")
	flag.Parse()

	viper.BindPFlag("key", flag.Lookup("key"))

	fmt.Println(viper.GetString("key"))  // Output: (value provided via --key)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Write configuration to a file
func main() {
	viper.Set("key", "newValue")
	viper.SetConfigFile("./config.yaml")

	if err := viper.WriteConfig(); err != nil {
		panic(err)
	}

	fmt.Println("Config written to file")
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Merge configuration from multiple files
func main() {
	viper.SetConfigFile("./config1.yaml")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	viper.SetConfigFile("./config2.yaml")
	if err := viper.MergeInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Retrieve all settings as a map
func main() {
	viper.Set("key1", "value1")
	viper.Set("key2", "value2")

	settings := viper.AllSettings()
	fmt.Println(settings)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as a boolean
func main() {
	viper.Set("key", true)

	value := viper.GetBool("key")
	fmt.Println(value)  // Output: true
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as an integer
func main() {
	viper.Set("key", 42)

	value := viper.GetInt("key")
	fmt.Println(value)  // Output: 42
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as a float
func main() {
	viper.Set("key", 42.42)

	value := viper.GetFloat64("key")
	fmt.Println(value)  // Output: 42.42
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Get a configuration value as a time duration
func main() {
	viper.Set("key", "1h")

	value := viper.GetDuration("key")
	fmt.Println(value)  // Output: 1h0m0s
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as a slice
func main() {
	viper.Set("key", []string{"value1", "value2"})

	value := viper.GetStringSlice("key")
	fmt.Println(value)  // Output: [value1 value2]
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as a map
func main() {
	viper.Set("key", map[string]string{"subkey": "subvalue"})

	value := viper.GetStringMapString("key")
	fmt.Println(value)  // Output: map[subkey:subvalue]
}





package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration from a JSON string
func main() {
	jsonStr := `{"key": "jsonValue"}`
	var data map[string]interface{}
	json.Unmarshal([]byte(jsonStr), &data)
	viper.MergeConfigMap(data)

	fmt.Println(viper.GetString("key"))  // Output: jsonValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Set configuration from a YAML string
func main() {
	yamlStr := `key: yamlValue`
	var data map[string]interface{}
	yaml.Unmarshal([]byte(yamlStr), &data)
	viper.MergeConfigMap(data)

	fmt.Println(viper.GetString("key"))  // Output: yamlValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Set configuration from environment variables with a prefix
func main() {
	_ = os.Setenv("APP_KEY", "envValue")
	viper.SetEnvPrefix("app")
	viper.BindEnv("key")

	fmt.Println(viper.GetString("key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Set configuration from environment variables automatically
func main() {
	_ = os.Setenv("APP_KEY", "envValue")
	viper.AutomaticEnv()

	fmt.Println(viper.GetString("APP_KEY"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set an alias for a configuration key
func main() {
	viper.Set("originalKey", "value")
	viper.RegisterAlias("aliasKey", "originalKey")

	fmt.Println(viper.GetString("aliasKey"))  // Output: value
}





package main

import (
	"fmt"
	"strings"
	"github.com/spf13/viper"
)

// Use a custom key replacer
func main() {
	viper.Set("custom.key", "value")
	viper.SetKeyDelimiter(".")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	fmt.Println(viper.GetString("custom_key"))  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle errors when reading the configuration file
func main() {
	viper.SetConfigFile("./config.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Error reading config file:", err)
	} else {
		fmt.Println("Config file read successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value with a fallback
func main() {
	viper.Set("key", "value")

	value := viper.GetString("missingKey")
	if value == "" {
		value = "fallbackValue"
	}

	fmt.Println(value)  // Output: fallbackValue
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Bind a configuration key to a command-line flag
func main() {
	key := flag.String("key", "default", "The key value")
	flag.Parse()

	viper.BindPFlag("key", flag.Lookup("key"))

	fmt.Println(viper.GetString("key"))  // Output: (value provided via --key)
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Bind all flags to Viper
func main() {
	key := flag.String("key", "default", "The key value")
	flag.Parse()

	viper.BindPFlags(flag.CommandLine)

	fmt.Println(viper.GetString("key"))  // Output: (value provided via --key)
}





package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Use Cobra command with Viper
func main() {
	var key string

	var rootCmd = &cobra.Command{
		Use:   "app",
		Short: "A brief description of your application",
		Run: func(cmd *cobra.Command, args []string) {
			viper.BindPFlag("key", cmd.Flags().Lookup("key"))
			fmt.Println(viper.GetString("key"))
		},
	}

	rootCmd.Flags().StringVarP(&key, "key", "k", "default", "The key value")
	cobra.CheckErr(rootCmd.Execute())
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
)

// Read configuration from a remote source
func main() {
	viper.AddRemoteProvider("consul", "localhost:8500", "path/to/config")
	viper.SetConfigType("json")  // Specify the type of configuration to retrieve

	err := viper.ReadRemoteConfig()
	if err != nil {
		log.Fatalf("Failed to read remote config: %v", err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Add multiple paths for configuration files
func main() {
	viper.AddConfigPath("/etc/appname/")
	viper.AddConfigPath("$HOME/.appname")
	viper.AddConfigPath(".")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Override configuration with environment variables
func main() {
	_ = os.Setenv("APP_KEY", "envValue")
	viper.BindEnv("key", "APP_KEY")
	viper.Set("key", "configValue")

	fmt.Println(viper.GetString("key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Merge multiple configuration maps
func main() {
	viper.Set("key1", "value1")

	moreConfig := map[string]interface{}{
		"key2": "value2",
	}

	viper.MergeConfigMap(moreConfig)

	fmt.Println(viper.GetString("key1"))  // Output: value1
	fmt.Println(viper.GetString("key2"))  // Output: value2
}





package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"os"
	"time"
)

// Watch environment variables for changes
func main() {
	_ = os.Setenv("APP_KEY", "envValue")
	viper.BindEnv("key", "APP_KEY")

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Environment variable changed")
	})

	for {
		time.Sleep(time.Second)
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Custom unmarshaler function
type Custom struct {
	Key string
}

func (c *Custom) UnmarshalText(text []byte) error {
	c.Key = string(text) + "_unmarshaled"
	return nil
}

// Use a custom unmarshaler
func main() {
	viper.Set("key", "value")

	var custom Custom
	viper.UnmarshalKey("key", &custom)

	fmt.Println(custom.Key)  // Output: value_unmarshaled
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Write a sub-configuration to a file
func main() {
	viper.Set("sub.key", "subValue")
	viper.SetConfigFile("./subconfig.yaml")

	if err := viper.WriteConfigAs("./subconfig.yaml"); err != nil {
		panic(err)
	}

	fmt.Println("Sub-configuration written to file")
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Retrieve all configuration keys
func main() {
	viper.Set("key1", "value1")
	viper.Set("key2", "value2")

	keys := viper.AllKeys()
	fmt.Println(keys)  // Output: [key1 key2]
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a nested configuration value
func main() {
	viper.Set("parent.child.key", "nestedValue")

	value := viper.GetString("parent.child.key")
	fmt.Println(value)  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Unmarshal configuration into nested structs
type Config struct {
	Parent struct {
		Child struct {
			Key string
		}
	}
}

func main() {
	viper.Set("parent.child.key", "nestedValue")

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Parent.Child.Key)  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Bind a configuration key to the content of a file
func main() {
	_ = os.WriteFile("keyfile", []byte("fileContent"), 0644)
	viper.BindConfigFile("key", "keyfile")

	fmt.Println(viper.GetString("key"))  // Output: fileContent
}





package main

import (
	"testing"
	"github.com/spf13/viper"
)

// Use Viper in tests
func TestViper(t *testing.T) {
	viper.Set("key", "testValue")

	if viper.GetString("key") != "testValue" {
		t.Error("Expected testValue")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with JSON tags
type Config struct {
	Key string `json:"key"`
}

func main() {
	viper.SetConfigType("json")
	viper.ReadConfig(strings.NewReader(`{"key": "jsonValue"}`))

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Key)  // Output: jsonValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with custom tags
type Config struct {
	Key string `mapstructure:"key"`
}

func main() {
	viper.Set("key", "value")

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Key)  // Output: value
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with command-line and config file
func main() {
	key := flag.String("key", "default", "The key value")
	flag.Parse()

	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()
	viper.BindPFlag("key", flag.Lookup("key"))

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration value from raw bytes
func main() {
	viper.Set("key", []byte("rawBytesValue"))

	value := viper.Get("key").([]byte)
	fmt.Println(string(value))  // Output: rawBytesValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Reset Viper configuration
func main() {
	viper.Set("key", "value")
	viper.Reset()

	if viper.IsSet("key") {
		fmt.Println("Key still exists")
	} else {
		fmt.Println("Key has been reset")  // Output: Key has been reset
	}
}





package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Log configuration changes
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Printf("Config file changed: %s\n", e.Name)
	})

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Ignore unexported struct fields
type Config struct {
	Exported   string
	unexported string
}

func main() {
	viper.Set("Exported", "exportedValue")
	viper.Set("unexported", "unexportedValue")

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Exported)    // Output: exportedValue
	fmt.Println(config.unexported)  // Output:
}





package main

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
)

// Load configuration from a byte buffer
func main() {
	var buffer bytes.Buffer
	buffer.WriteString(`key: bufferValue`)

	viper.SetConfigType("yaml")
	viper.ReadConfig(&buffer)

	fmt.Println(viper.GetString("key"))  // Output: bufferValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"strings"
)

// Use environment variables with a custom delimiter
func main() {
	_ = os.Setenv("APP__KEY", "envValue")
	viper.SetEnvKeyReplacer(strings.NewReplacer("__", "."))
	viper.AutomaticEnv()

	fmt.Println(viper.GetString("app.key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Ignore missing configuration file
func main() {
	viper.SetConfigFile("./missing-config.yaml")
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Config file found and read successfully")
	} else {
		fmt.Println("Config file not found or could not be read, ignoring...")
	}
}





package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Watch configuration files for changes
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
	})

	select {}  // Block forever
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get all configuration settings as a map
func main() {
	viper.Set("key1", "value1")
	viper.Set("key2", "value2")

	settings := viper.AllSettings()
	fmt.Println(settings)  // Output: map[key1:value1 key2:value2]
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration from JSON file
func main() {
	viper.SetConfigFile("./config.json")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from config.json)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration from YAML file
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from config.yaml)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use nested struct tags with Viper
type Config struct {
	Parent struct {
		Child struct {
			Key string `mapstructure:"key"`
		} `mapstructure:"child"`
	} `mapstructure:"parent"`
}

func main() {
	viper.Set("parent.child.key", "nestedValue")

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Parent.Child.Key)  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Check if configuration key exists
func main() {
	viper.Set("key", "value")

	if viper.IsSet("key") {
		fmt.Println("Key exists")  // Output: Key exists
	} else {
		fmt.Println("Key does not exist")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as an integer
func main() {
	viper.Set("key", 123)

	value := viper.GetInt("key")
	fmt.Println(value)  // Output: 123
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get a configuration value as a boolean
func main() {
	viper.Set("key", true)

	value := viper.GetBool("key")
	fmt.Println(value)  // Output: true
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration from TOML file
func main() {
	viper.SetConfigFile("./config.toml")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from config.toml)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
)

// Set configuration from a remote source with custom type
func main() {
	viper.AddRemoteProvider("etcd", "localhost:2379", "/config")
	viper.SetConfigType("yaml")

	err := viper.ReadRemoteConfig()
	if err != nil {
		log.Fatalf("Failed to read remote config: %v", err)
	}

	fmt.Println(viper.GetString("key"))
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"strings"
)

// Use key replacer for nested configuration
func main() {
	viper.Set("parent.child.key", "nestedValue")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))
	viper.AutomaticEnv()

	fmt.Println(viper.GetString("parent__child__key"))  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration with function
func main() {
	viper.Set("key", func() string { return "functionValue" }())

	fmt.Println(viper.GetString("key"))  // Output: functionValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use configuration sub-tree
func main() {
	viper.Set("parent.child.key", "nestedValue")

	sub := viper.Sub("parent.child")
	fmt.Println(sub.GetString("key"))  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Bind to configuration files with different formats
func main() {
	viper.SetConfigFile("./config.json")
	viper.ReadInConfig()
	viper.SetConfigFile("./config.yaml")
	viper.MergeInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from either config.json or config.yaml)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get configuration value with default
func main() {
	viper.SetDefault("key", "defaultValue")

	fmt.Println(viper.GetString("key"))  // Output: defaultValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration key case insensitive
func main() {
	viper.Set("KEY", "value")

	fmt.Println(viper.GetString("key"))  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Unmarshal configuration into multiple structs
type Config1 struct {
	Key1 string
}

type Config2 struct {
	Key2 string
}

func main() {
	viper.Set("key1", "value1")
	viper.Set("key2", "value2")

	var config1 Config1
	var config2 Config2
	viper.Unmarshal(&config1)
	viper.Unmarshal(&config2)

	fmt.Println(config1.Key1)  // Output: value1
	fmt.Println(config2.Key2)  // Output: value2
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"strings"
)

// Unmarshal configuration from reader
func main() {
	reader := strings.NewReader(`key: value`)

	viper.SetConfigType("yaml")
	viper.ReadConfig(reader)

	fmt.Println(viper.GetString("key"))  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration using a struct
type Config struct {
	Key string
}

func main() {
	config := Config{Key: "value"}
	viper.Set("config", config)

	fmt.Println(viper.GetStringMap("config"))  // Output: map[Key:value]
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Register custom config type
func main() {
	viper.SetConfigType("custom")

	fmt.Println(viper.GetString("key"))  // Output: (based on custom type handling)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle configuration errors gracefully
func main() {
	viper.SetConfigFile("./invalid-config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("Error reading config:", err)
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Get configuration value as a duration
func main() {
	viper.Set("timeout", "5s")

	duration := viper.GetDuration("timeout")
	fmt.Println(duration)  // Output: 5s
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get configuration value as a float
func main() {
	viper.Set("key", 123.45)

	value := viper.GetFloat64("key")
	fmt.Println(value)  // Output: 123.45
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Bind configuration to struct with default values
type Config struct {
	Key1 string
	Key2 int
}

func main() {
	viper.SetDefault("key1", "defaultValue")
	viper.SetDefault("key2", 42)

	var config Config
	viper.Unmarshal(&config)

	fmt.Println(config.Key1)  // Output: defaultValue
	fmt.Println(config.Key2)  // Output: 42
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Read configuration with optional key
func main() {
	value := viper.GetString("optionalKey")
	if value == "" {
		fmt.Println("Key not set, using default value")
	} else {
		fmt.Println("Key value:", value)
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Override configuration values
func main() {
	viper.Set("key", "initialValue")
	viper.Set("key", "overriddenValue")

	fmt.Println(viper.GetString("key"))  // Output: overriddenValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Use environment variables with Viper
func main() {
	_ = os.Setenv("KEY", "envValue")
	viper.BindEnv("key")

	fmt.Println(viper.GetString("key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Check for unused keys
type Config struct {
	Key1 string
}

func main() {
	viper.Set("key1", "value1")
	viper.Set("unusedKey", "value")

	var config Config
	viper.Unmarshal(&config)

	for _, key := range viper.AllKeys() {
		if !viper.InConfig(key) {
			fmt.Println("Unused key:", key)  // Output: Unused key: unusedKey
		}
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get configuration value from nested maps
func main() {
	viper.Set("parent.child.key", "nestedValue")

	value := viper.GetString("parent.child.key")
	fmt.Println(value)  // Output: nestedValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"strconv"
)

// Set configuration value with custom type conversion
func main() {
	viper.Set("key", "123")

	value, _ := strconv.Atoi(viper.GetString("key"))
	fmt.Println(value)  // Output: 123
}





package main

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
)

// Validate configuration
func main() {
	viper.Set("key", "value")

	if err := validateConfig(); err != nil {
		fmt.Println("Validation error:", err)
	} else {
		fmt.Println("Configuration is valid")
	}
}

func validateConfig() error {
	if viper.GetString("key") == "" {
		return errors.New("key is required")
	}
	return nil
}





package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
)

// Marshal configuration into JSON
func main() {
	viper.Set("key", "value")

	configJSON, _ := json.Marshal(viper.AllSettings())
	fmt.Println(string(configJSON))  // Output: {"key":"value"}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Merge multiple configuration maps
func main() {
	viper.Set("key1", "value1")

	otherConfig := map[string]interface{}{"key2": "value2"}
	viper.MergeConfigMap(otherConfig)

	fmt.Println(viper.GetString("key1"))  // Output: value1
	fmt.Println(viper.GetString("key2"))  // Output: value2
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with FlagSet
func main() {
	fs := flag.NewFlagSet("example", flag.ContinueOnError)
	fs.String("key", "default", "Description of the key")

	viper.BindFlagSet(fs)

	fs.Parse([]string{"--key", "flagValue"})
	fmt.Println(viper.GetString("key"))  // Output: flagValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Add custom configuration file paths
func main() {
	viper.AddConfigPath("./config")
	viper.AddConfigPath("./settings")

	viper.SetConfigName("config")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from one of the config paths)
}





package main

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Handle configuration reload errors
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
		if err := viper.ReadInConfig(); err != nil {
			fmt.Println("Error reloading config:", err)
		}
	})

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Load configuration with custom name
func main() {
	viper.SetConfigName("custom-config")
	viper.AddConfigPath("./")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from custom-config file)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Get configuration value as time.Time
func main() {
	viper.Set("timestamp", "2022-01-01T00:00:00Z")

	timestamp, _ := time.Parse(time.RFC3339, viper.GetString("timestamp"))
	fmt.Println(timestamp)  // Output: 2022-01-01 00:00:00 +0000 UTC
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration value with slice
func main() {
	viper.Set("key", []string{"value1", "value2"})

	values := viper.GetStringSlice("key")
	fmt.Println(values)  // Output: [value1 value2]
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Override configuration with flags
func main() {
	fs := flag.NewFlagSet("example", flag.ContinueOnError)
	fs.String("key", "defaultValue", "Description of the key")

	viper.BindFlagSet(fs)
	fs.Parse([]string{"--key", "flagValue"})

	fmt.Println(viper.GetString("key"))  // Output: flagValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle configuration loading errors
func main() {
	viper.SetConfigFile("./invalid-config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("Error reading config:", err)
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Use configuration with time durations
func main() {
	viper.Set("timeout", "5s")

	timeout := viper.GetDuration("timeout")
	fmt.Println(timeout)  // Output: 5s
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
)

// Log configuration load errors
func main() {
	viper.SetConfigFile("./invalid-config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		log.Fatalf("Error reading config: %v", err)
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Set configuration value as map
func main() {
	viper.Set("key", map[string]interface{}{"subkey": "value"})

	value := viper.GetStringMap("key")
	fmt.Println(value)  // Output: map[subkey:value]
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use configuration with custom file name
func main() {
	viper.SetConfigName("my-config")
	viper.AddConfigPath("./")
	viper.ReadInConfig()

	fmt.Println(viper.GetString("key"))  // Output: (value from my-config file)
}





package main

import (
	"fmt"
	"github.com/pelletier/go-toml"
	"github.com/spf13/viper"
)

// Marshal configuration into TOML
func main() {
	viper.Set("key", "value")

	configTOML, _ := toml.Marshal(viper.AllSettings())
	fmt.Println(string(configTOML))  // Output: (TOML representation of configuration)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Get configuration value as interface{}
func main() {
	viper.Set("key", "value")

	value := viper.Get("key")
	fmt.Println(value)  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Use Viper for command-line application
func main() {
	var rootCmd = &cobra.Command{
		Use: "app",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Config key value:", viper.GetString("key"))
		},
	}

	rootCmd.PersistentFlags().String("key", "defaultValue", "Description of the key")
	viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))

	rootCmd.Execute()
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Use multiple configuration providers
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()
	viper.AutomaticEnv()

	_ = os.Setenv("KEY", "envValue")
	viper.BindEnv("key")

	fmt.Println(viper.GetString("key"))  // Output: (value from env or file)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Save configuration to file
func main() {
	viper.Set("key", "value")

	file, _ := os.Create("./saved-config.yaml")
	defer file.Close()

	viper.WriteConfigAs(file.Name())
	fmt.Println("Config saved to", file.Name())
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"strings"
)

// Use custom delimiter for environment variables
func main() {
	_ = os.Setenv("APP__KEY", "envValue")
	viper.SetEnvKeyReplacer(strings.NewReplacer("__", "."))
	viper.AutomaticEnv()

	fmt.Println(viper.GetString("app.key"))  // Output: envValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle errors in configuration loading
func main() {
	viper.SetConfigFile("./missing-config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("Error reading config:", err)
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Dynamically update configuration
func main() {
	viper.Set("key", "initialValue")

	go func() {
		time.Sleep(2 * time.Second)
		viper.Set("key", "updatedValue")
	}()

	for {
		fmt.Println(viper.GetString("key"))  // Output: initialValue (then updates to updatedValue)
		time.Sleep(1 * time.Second)
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use configuration with aliases
func main() {
	viper.Set("key", "value")
	viper.RegisterAlias("aliasKey", "key")

	fmt.Println(viper.GetString("aliasKey"))  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
)

// Read configuration from multiple sources
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()
	viper.AutomaticEnv()

	_ = os.Setenv("KEY", "envValue")
	viper.BindEnv("key")

	fmt.Println(viper.GetString("key"))  // Output: (value from env or file)
}





package main

import (
	"encoding/xml"
	"fmt"
	"github.com/spf13/viper"
)

// Marshal configuration into XML
func main() {
	viper.Set("key", "value")

	configXML, _ := xml.Marshal(viper.AllSettings())
	fmt.Println(string(configXML))  // Output: (XML representation of configuration)
}





package main

import (
	"flag"
	"fmt"
	"github.com/spf13/viper"
)

// Bind command-line flags to Viper
func main() {
	fs := flag.NewFlagSet("example", flag.ContinueOnError)
	fs.String("key", "defaultValue", "Description of the key")

	viper.BindFlagSet(fs)
	fs.Parse([]string{"--key", "flagValue"})

	fmt.Println(viper.GetString("key"))  // Output: flagValue
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle missing configuration file
func main() {
	viper.SetConfigFile("./missing-config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("Configuration file not found, proceeding with defaults")
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"net/http"
	"io/ioutil"
)

// Load configuration from a remote source
func main() {
	resp, err := http.Get("https://example.com/config.yaml")
	if err != nil {
		fmt.Println("Error fetching config:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading config:", err)
		return
	}

	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(body))

	fmt.Println(viper.GetString("key"))  // Output: (value from remote config)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/fsnotify/fsnotify"
)

// Use custom file watcher with Viper
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()

	watcher.Add("./config.yaml")

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					viper.ReadInConfig()
					fmt.Println("Config file updated:", viper.AllSettings())
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Println("Watcher error:", err)
			}
		}
	}()

	select {}
}





package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
)

// Get configuration value as JSON
func main() {
	viper.Set("key", "value")

	valueJSON, _ := json.Marshal(viper.AllSettings())
	fmt.Println(string(valueJSON))  // Output: {"key":"value"}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Integrate Viper with custom CLI framework
func main() {
	// Example custom CLI framework setup
	// (Custom logic to handle CLI arguments)

	viper.Set("key", "valueFromCLI")

	fmt.Println(viper.GetString("key"))  // Output: valueFromCLI
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with custom encoding
func main() {
	viper.SetConfigType("custom")

	// Example: Custom encoding handler (details omitted)
	viper.ReadConfig(customReader)

	fmt.Println(viper.GetString("key"))  // Output: (based on custom encoding)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Dynamic configuration reloading
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	go func() {
		for {
			time.Sleep(10 * time.Second)
			viper.ReadInConfig()
			fmt.Println("Config reloaded:", viper.AllSettings())
		}
	}()

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Custom configuration decoders
func main() {
	viper.SetConfigType("custom")

	// Example: Custom decoder (details omitted)
	viper.ReadConfig(customDecoder)

	fmt.Println(viper.GetString("key"))  // Output: (based on custom decoder)
}





package main

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
)

// Load configuration from multiple remote sources
func main() {
	resp1, _ := http.Get("https://example.com/config1.yaml")
	body1, _ := ioutil.ReadAll(resp1.Body)
	defer resp1.Body.Close()

	resp2, _ := http.Get("https://example.com/config2.yaml")
	body2, _ := ioutil.ReadAll(resp2.Body)
	defer resp2.Body.Close()

	viper.SetConfigType("yaml")
	viper.ReadConfig(bytes.NewBuffer(body1))
	viper.MergeConfig(bytes.NewBuffer(body2))

	fmt.Println(viper.AllSettings())  // Output: (combined values from both remote configs)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Custom error handling for Viper
func main() {
	viper.SetConfigFile("./config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("Custom error handling:", err)
		// Custom handling logic
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"net/http"
)

// Handle configuration loading in a web server
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Config key value: %s", viper.GetString("key"))
	})

	http.ListenAndServe(":8080", nil)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with custom configuration formats
func main() {
	viper.SetConfigType("custom")

	// Example: Custom configuration format (details omitted)
	viper.ReadConfig(customFormatReader)

	fmt.Println(viper.GetString("key"))  // Output: (based on custom format)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Monitor configuration changes from multiple sources
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
	})

	go func() {
		for {
			time.Sleep(10 * time.Second)
			// Check remote source and merge changes
			viper.ReadRemoteConfig() // Example (details omitted)
			fmt.Println("Remote config reloaded:", viper.AllSettings())
		}
	}()

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Serialize configuration to custom format
func main() {
	viper.Set("key", "value")

	// Example: Serialize to custom format (details omitted)
	customConfig := serializeToCustomFormat(viper.AllSettings())

	fmt.Println(customConfig)
}





package main

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
)

// Load configuration with custom validators
func main() {
	viper.SetConfigFile("./config.yaml")
	err := viper.ReadInConfig()

	if err == nil {
		err = validateConfig()
	}

	if err != nil {
		fmt.Println("Configuration error:", err)
	} else {
		fmt.Println("Configuration is valid")
	}
}

func validateConfig() error {
	if viper.GetString("key") == "" {
		return errors.New("key is required")
	}
	return nil
}





package main

import (
	"context"
	"fmt"
	"github.com/spf13/viper"
	"github.com/aws/aws-lambda-go/lambda"
)

// Load configuration in serverless environment
func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context) (string, error) {
	viper.SetConfigFile("/var/task/config.yaml")  // Lambda function file system
	viper.ReadInConfig()

	return fmt.Sprintf("Config key value: %s", viper.GetString("key")), nil
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with custom configuration loader
func main() {
	viper.SetConfigType("custom")

	// Example: Custom configuration loader (details omitted)
	viper.ReadConfig(customLoader)

	fmt.Println(viper.GetString("key"))  // Output: (based on custom loader)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Load configuration from multiple files
func main() {
	viper.SetConfigFile("./config1.yaml")
	viper.ReadInConfig()
	viper.MergeInConfig("./config2.yaml")

	fmt.Println(viper.AllSettings())  // Output: (combined values from both files)
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	// Assuming some encryption package
	// "github.com/example/encryption"
)

// Secure configuration with encryption
func main() {
	encryptedValue := encrypt("sensitiveValue")

	viper.Set("key", encryptedValue)

	decryptedValue := decrypt(viper.GetString("key"))
	fmt.Println("Decrypted value:", decryptedValue)  // Output: sensitiveValue
}

func encrypt(value string) string {
	// Encryption logic (details omitted)
	return value
}

func decrypt(value string) string {
	// Decryption logic (details omitted)
	return value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"time"
)

// Monitor configuration changes in Kubernetes
func main() {
	viper.SetConfigFile("/etc/config/config.yaml")
	viper.ReadInConfig()

	go func() {
		for {
			time.Sleep(10 * time.Second)
			viper.ReadInConfig()
			fmt.Println("Config reloaded:", viper.AllSettings())
		}
	}()

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Use Viper with configuration versioning
func main() {
	viper.SetConfigFile("./config-v1.yaml")
	viper.ReadInConfig()

	version := viper.GetString("version")
	if version != "1.0" {
		fmt.Println("Unsupported configuration version")
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
)

// Use Viper with custom loggers
func main() {
	viper.SetConfigFile("./config.yaml")
	err := viper.ReadInConfig()

	if err != nil {
		log.Fatalf("Custom logger: Error reading config: %v", err)
	} else {
		fmt.Println("Config loaded successfully")
	}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle nested configuration structures
func main() {
	viper.Set("nested.key", "value")

	fmt.Println(viper.GetString("nested.key"))  // Output: value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	// Assuming some encryption package
	// "github.com/example/encryption"
)

// Use Viper with custom encryption
func main() {
	viper.Set("key", encrypt("sensitiveValue"))

	value := decrypt(viper.GetString("key"))
	fmt.Println("Decrypted value:", value)  // Output: sensitiveValue
}

func encrypt(value string) string {
	// Encryption logic (details omitted)
	return value
}

func decrypt(value string) string {
	// Decryption logic (details omitted)
	return value
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
	"github.com/fsnotify/fsnotify"
)

// Load configuration with automatic reload
func main() {
	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
	})

	select {}
}





package main

import (
	"fmt"
	"github.com/spf13/viper"
)

// Handle configuration in microservices
func main() {
	viper.SetConfigFile("./service-config.yaml")
	viper.ReadInConfig()

	fmt.Println("Service config key value:", viper.GetString("serviceKey"))
}










