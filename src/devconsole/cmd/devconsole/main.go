// devconsole — la console temps réel du DEV-TEST (issue #329). Voir le paquet devconsole.
//
//	devconsole serve --listen ADDR:PORT --view-key-file F --ingest-key-file F [--label L]
//	devconsole ship  --console URL --key-file F --machine M1|M2 [--trace F]... [--log F] --run-dir D --admin-sock S [--opa-sock S] [--app-url U]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	devconsole "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devconsole"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func readKey(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("a key file is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must not be readable by others (chmod 600)", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: devconsole serve|ship …")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(ctx, os.Args[2:])
	case "ship":
		err = ship(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "devconsole:", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "address:port to listen on")
	vk := fs.String("view-key-file", "", "file holding the key that opens the page")
	ik := fs.String("ingest-key-file", "", "file holding the key the machines send events with")
	label := fs.String("label", "", "environment label shown in the header")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *listen == "" {
		return fmt.Errorf("--listen is required")
	}
	view, err := readKey(*vk)
	if err != nil {
		return fmt.Errorf("view key: %w", err)
	}
	ingest, err := readKey(*ik)
	if err != nil {
		return fmt.Errorf("ingest key: %w", err)
	}
	srv, err := devconsole.NewServer(devconsole.Config{ViewKey: view, IngestKey: ingest, Label: *label}, devconsole.NewStore(nil))
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = hs.Shutdown(sc)
	}()
	log.Printf("devconsole: listening on http://%s (plain HTTP, test only; read-only; two keys)", *listen)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func ship(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ship", flag.ContinueOnError)
	var traces multi
	url := fs.String("console", "", "console URL, e.g. http://10.0.0.5:9100")
	kf := fs.String("key-file", "", "file holding the ingest key")
	machine := fs.String("machine", "", "M1 or M2")
	fs.Var(&traces, "trace", "trace file to follow (repeatable)")
	logf := fs.String("log", "", "brokerd.log (M1): refused TLS handshakes")
	run := fs.String("run-dir", "", "directory of the .pid files")
	admin := fs.String("admin-sock", "", "admin socket of brokerd (M1) or pepd (M2)")
	opa := fs.String("opa-sock", "", "OPA socket")
	app := fs.String("app-url", "", "application URL (M2)")
	every := fs.Duration("every", 2*time.Second, "state report period")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := readKey(*kf)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	return devconsole.Ship(ctx, devconsole.ShipConfig{ConsoleURL: *url, Key: key, Machine: *machine, TraceFiles: traces,
		LogFile: *logf, RunDir: *run, AdminSock: *admin, OPASock: *opa, AppURL: *app, Interval: *every})
}
