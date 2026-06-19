// gha-deploy: an OIDC-gated Kubernetes deploy operator.
//
// A GitHub Actions workflow requests an OIDC token and POSTs it to /deploy.
// The operator verifies the token's signature against GitHub's JWKS and checks
// its claims (repository / ref / aud) against an allowlist, then performs the
// requested deploy (set image + wait for rollout) using its in-cluster
// ServiceAccount. No kubeconfig, no static secrets, no self-hosted runner, and
// the kube API is never exposed — only this operator is.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// Rule is one allowlist entry: a repo (and optionally a ref) may deploy to the
// listed namespaces.
type Rule struct {
	Repository string   `json:"repository"`        // e.g. "optradercards/shiny-sync"
	Ref        string   `json:"ref,omitempty"`     // e.g. "refs/heads/main"; empty = any ref
	Namespaces []string `json:"namespaces"`        // allowed namespaces; "*" = any
}

type Config struct {
	Issuer   string `json:"issuer"`   // default https://token.actions.githubusercontent.com
	Audience string `json:"audience"` // required; the aud the workflow requests
	Rules    []Rule `json:"rules"`
}

// ghaClaims are the GitHub Actions OIDC claims we authorize against.
type ghaClaims struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Sub        string `json:"sub"`
	Actor      string `json:"actor"`
	Workflow   string `json:"workflow"`
}

type setImage struct {
	Deployment string `json:"deployment"`
	Container  string `json:"container,omitempty"` // optional if the deployment has a single container
	Image      string `json:"image"`
}

type deployReq struct {
	Namespace      string     `json:"namespace"`
	SetImage       []setImage `json:"setImage"`
	Wait           []string   `json:"wait"` // deployments to rollout-wait; defaults to the setImage targets
	TimeoutSeconds int        `json:"timeoutSeconds"`
}

type server struct {
	cfg      Config
	verifier *oidc.IDTokenVerifier
	k8s      *kubernetes.Clientset
}

func main() {
	var cfgPath, addr string
	flag.StringVar(&cfgPath, "config", envOr("CONFIG_PATH", "/etc/gha-deploy/config.yaml"), "config file")
	flag.StringVar(&addr, "addr", envOr("LISTEN_ADDR", ":8080"), "listen address")
	flag.Parse()

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "https://token.actions.githubusercontent.com"
	}
	if cfg.Audience == "" {
		log.Fatal("config: audience is required")
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		log.Fatalf("oidc provider %q: %v", cfg.Issuer, err)
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("in-cluster config: %v", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		log.Fatalf("k8s client: %v", err)
	}

	s := &server{cfg: cfg, verifier: provider.Verifier(&oidc.Config{ClientID: cfg.Audience}), k8s: cs}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/deploy", s.handleDeploy)
	log.Printf("gha-deploy on %s (issuer=%s aud=%s rules=%d)", addr, cfg.Issuer, cfg.Audience, len(cfg.Rules))
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	raw := bearer(r)
	if raw == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	idt, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var cl ghaClaims
	if err := idt.Claims(&cl); err != nil {
		http.Error(w, "bad claims", http.StatusUnauthorized)
		return
	}

	var req deployReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Namespace == "" {
		http.Error(w, "namespace required", http.StatusBadRequest)
		return
	}

	if !s.authorized(cl, req.Namespace) {
		log.Printf("DENY repo=%q ref=%q ns=%q", cl.Repository, cl.Ref, req.Namespace)
		http.Error(w, fmt.Sprintf("not authorized: repo=%s ref=%s ns=%s", cl.Repository, cl.Ref, req.Namespace), http.StatusForbidden)
		return
	}
	log.Printf("ALLOW repo=%q ref=%q actor=%q ns=%q setImage=%d wait=%d", cl.Repository, cl.Ref, cl.Actor, req.Namespace, len(req.SetImage), len(req.Wait))

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	results := map[string]string{}

	for _, si := range req.SetImage {
		if err := s.applyImage(ctx, req.Namespace, si); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("setImage %s: %v", si.Deployment, err), "results": results})
			return
		}
		results[si.Deployment] = "image=" + si.Image
	}

	wait := req.Wait
	if len(wait) == 0 {
		for _, si := range req.SetImage {
			wait = append(wait, si.Deployment)
		}
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, name := range wait {
		if err := s.waitRollout(wctx, req.Namespace, name); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": fmt.Sprintf("rollout %s: %v", name, err), "results": results})
			return
		}
		results[name] = "rolled out"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "results": results})
}

func (s *server) authorized(cl ghaClaims, ns string) bool {
	for _, rule := range s.cfg.Rules {
		if rule.Repository != cl.Repository {
			continue
		}
		if rule.Ref != "" && rule.Ref != cl.Ref {
			continue
		}
		for _, n := range rule.Namespaces {
			if n == ns || n == "*" {
				return true
			}
		}
	}
	return false
}

func (s *server) applyImage(ctx context.Context, ns string, si setImage) error {
	if si.Deployment == "" || si.Image == "" {
		return errors.New("deployment and image required")
	}
	container := si.Container
	if container == "" {
		d, err := s.k8s.AppsV1().Deployments(ns).Get(ctx, si.Deployment, metav1.GetOptions{})
		if err != nil {
			return err
		}
		c := d.Spec.Template.Spec.Containers
		if len(c) != 1 {
			return fmt.Errorf("container must be specified (deployment has %d)", len(c))
		}
		container = c[0].Name
	}
	patch := fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":%q,"image":%q}]}}}}`, container, si.Image)
	_, err := s.k8s.AppsV1().Deployments(ns).Patch(ctx, si.Deployment, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{FieldManager: "gha-deploy"})
	return err
}

// waitRollout blocks until the Deployment's rollout is complete (the kubectl
// rollout status check) or ctx is cancelled.
func (s *server) waitRollout(ctx context.Context, ns, name string) error {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		d, err := s.k8s.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		st := d.Status
		if d.Generation <= st.ObservedGeneration &&
			st.UpdatedReplicas >= want &&
			st.Replicas == st.UpdatedReplicas &&
			st.AvailableReplicas >= st.UpdatedReplicas {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout (updated=%d/%d available=%d)", st.UpdatedReplicas, want, st.AvailableReplicas)
		case <-t.C:
		}
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return v
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(p string) (Config, error) {
	var c Config
	b, err := os.ReadFile(p)
	if err != nil {
		return c, err
	}
	return c, yaml.Unmarshal(b, &c)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
