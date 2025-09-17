// Package main реализует DNS-сервер на порту 5053
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"dns-server/goresolver"
)

// DNSServer представляет DNS-сервер
type DNSServer struct {
	resolver *goresolver.Resolver
	server   *dns.Server
}

// NewDNSServer создает новый DNS-сервер
func NewDNSServer() (*DNSServer, error) {
	// Создаем резолвер
	resolver, err := goresolver.NewResolver("")
	if err != nil {
		return nil, err
	}

	return &DNSServer{
		resolver: resolver,
	}, nil
}

// handleDNSRequest обрабатывает входящие DNS-запросы
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Создаем ответ
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.Compress = true

	// Проверяем, есть ли вопросы
	if len(r.Question) == 0 {
		reply.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(reply)
		return
	}

	// Берем первый вопрос
	question := r.Question[0]
	qname := question.Name
	qtype := question.Qtype

	log.Printf("Получен запрос: %s (тип %s)", qname, dns.TypeToString[qtype])

	// Выполняем разрешение через ваш резолвер
	response, err := s.resolver.Query(qname, qtype)
	
	if err != nil {
		log.Printf("Ошибка разрешения для %s: %v", qname, err)
		
		// Устанавливаем соответствующий код ошибки
		switch err {
		case goresolver.ErrNoResult, goresolver.ErrNoData:
			reply.SetRcode(r, dns.RcodeNameError)
		case goresolver.ErrInvalidQuery:
			reply.SetRcode(r, dns.RcodeFormatError)
		case goresolver.ErrDNSSECValidationFailed:
			reply.SetRcode(r, dns.RcodeServFail)
		default:
			reply.SetRcode(r, dns.RcodeServerFailure)
		}
		
		w.WriteMsg(reply)
		return
	}

	// Копируем данные из ответа резолвера
	if response != nil {
		reply.Answer = response.Answer
		reply.Ns = response.Ns
		reply.Extra = response.Extra
		reply.Rcode = response.Rcode
		
		// Копируем флаги DNSSEC
		reply.MsgHdr.AuthenticatedData = response.MsgHdr.AuthenticatedData
		reply.MsgHdr.CheckingDisabled = response.MsgHdr.CheckingDisabled
	}

	// Отправляем ответ
	if err := w.WriteMsg(reply); err != nil {
		log.Printf("Ошибка отправки ответа: %v", err)
	}
}

// Start запускает DNS-сервер
func (s *DNSServer) Start(addr string) error {
	// Создаем mux для обработки запросов
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)

	// Создаем UDP сервер
	s.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
		UDPSize: 65535,
	}

	log.Printf("Запуск DNS-сервера на %s", addr)
	
	// Запускаем сервер
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Printf("Ошибка сервера: %v", err)
		}
	}()

	// Запускаем TCP сервер
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("Ошибка TCP сервера: %v", err)
		}
	}()

	return nil
}

// Stop останавливает сервер
func (s *DNSServer) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

func main() {
	log.Println("Инициализация DNS-сервера на порту 5053...")

	// Создаем сервер
	server, err := NewDNSServer()
	if err != nil {
		log.Fatalf("Ошибка создания сервера: %v", err)
	}

	// Запускаем сервер на порту 5053
	if err := server.Start(":5053"); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}

	log.Println("DNS-сервер запущен и готов принимать запросы на порту 5053")

	// Обработка сигналов завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Ожидаем сигнала завершения
	<-sigChan
	log.Println("Получен сигнал завершения, останавливаем сервер...")

	// Останавливаем сервер
	if err := server.Stop(); err != nil {
		log.Printf("Ошибка остановки сервера: %v", err)
	}

	// Небольшая задержка для корректного завершения
	time.Sleep(100 * time.Millisecond)
	log.Println("Сервер остановлен")
}
