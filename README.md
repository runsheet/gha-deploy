# gha-deploy

A tiny **OIDC-gated Kubernetes deploy operator** for GitHub Actions.

Your workflow asks GitHub for an OIDC token and POSTs it to the operator. The
operator **verifies the token against GitHub's JWKS**, checks its claims
(`repository` / `ref` / `aud`) against an **allowlist**, then performs the
deploy with its own in-cluster ServiceAccount and **waits for the rollout** —
returning success/failure so your Actions run goes green/red.

### Why
- **Keyless** — no kubeconfig, no static deploy tokens in GitHub secrets.
- **API never exposed** — only this small operator is reachable; the kube API isn't.
- **No self-hosted runner** — works from normal GitHub-hosted runners.
- **Scoped** — the operator's RBAC bounds exactly what (and where) it can deploy.
- **Visible** — it waits for `rollout status`, so CI reflects the real result.

```
GitHub Action (id-token: write)
  └─ POST /deploy  (Authorization: Bearer <OIDC>)  { namespace, setImage, wait }
        │  verify JWT sig (GitHub JWKS) + claims vs allowlist
        ▼
     set image  →  wait for rollout  →  200 / 5xx
```

## Install
```bash
kubectl apply -f deploy/operator.yaml      # edit image/config/RoleBindings first
```
Expose `gha-deploy` (Service, port 80 → 8080) to your CI however you reach the
cluster — e.g. an Ingress at `deploy.example.com`. The operator does its own
auth, so don't put an interactive auth layer (SSO) in front of it.

## Configure (`config.yaml`)
```yaml
issuer: https://token.actions.githubusercontent.com
audience: gha-deploy
rules:
  - repository: optradercards/shiny-sync
    ref: refs/heads/main      # omit for any ref
    namespaces: [optrader]
```
Grant the operator RBAC only in the namespaces you list (see `deploy/operator.yaml`).

## Use from a workflow
```yaml
permissions:
  id-token: write          # required to mint the OIDC token
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: runsheet/gha-deploy@v1
        with:
          url: https://deploy.example.com/deploy
          audience: gha-deploy
          namespace: optrader
          set-image: |
            [{"deployment":"pokemon","image":"ghcr.io/optradercards/shiny-sync:${{ github.sha }}"}]
          wait: pokemon
```

## Request API
`POST /deploy` with `Authorization: Bearer <GitHub OIDC token>`:
```json
{
  "namespace": "optrader",
  "setImage": [{"deployment":"pokemon","container":"pokemon","image":"ghcr.io/...:sha"}],
  "wait": ["pokemon"],
  "timeoutSeconds": 120
}
```
`container` is optional when the Deployment has a single container. `wait`
defaults to the `setImage` targets.

## Security notes
- The operator is the **only** exposed surface; protect what it can do via RBAC.
- Pin `rules[].ref` (e.g. `refs/heads/main`) so only trusted refs deploy.
- Claims are GitHub-signed and verified, so they can't be forged.

## Roadmap
- v1 (now): OIDC gate + `setImage` + rollout wait.
- v2: full `kubectl apply` of posted manifests (server-side apply).

MIT licensed.
