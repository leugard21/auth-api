package utils

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

type gzipResponseWriter struct {
	http.ResponseWriter
	writer io.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

func GzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		if enc := w.Header().Get("Content-Encoding"); enc != "" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length") // length changes after compression

		gz := gzip.NewWriter(w)
		defer gz.Close()

		grw := &gzipResponseWriter{
			ResponseWriter: w,
			writer:         gz,
		}

		next.ServeHTTP(grw, r)
	})
}
